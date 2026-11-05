package notify

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/syslog-yard/syslog-bucket/internal/store"
)

func TestWebhookRefusesLoopback(t *testing.T) {
	hit := false
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hit = true }))
	defer srv.Close()
	d := New(nil)
	ch := store.Channel{Kind: "slack", Config: json.RawMessage(`{"url":"` + srv.URL + `"}`)}
	err := d.deliver(context.Background(), ch, store.Entry{}, "x")
	if !errors.Is(err, errBlockedAddr) {
		t.Fatalf("err = %v, want blocked address", err)
	}
	if hit {
		t.Error("loopback endpoint was reached")
	}
	if strings.Contains(err.Error(), srv.URL) {
		t.Errorf("error leaks the webhook URL: %v", err)
	}
}

func TestBlockedAddr(t *testing.T) {
	for addr, want := range map[string]bool{
		"127.0.0.1": true, "::1": true, "0.0.0.0": true, "::": true,
		"169.254.169.254": true, "fe80::1": true, "::ffff:127.0.0.1": true,
		"10.0.0.5": false, "172.18.0.4": false, "192.168.1.10": false, "8.8.8.8": false,
	} {
		if got := blockedAddr(netip.MustParseAddr(addr)); got != want {
			t.Errorf("blockedAddr(%s) = %v, want %v", addr, got, want)
		}
	}
}

func TestWebhookDoesNotFollowRedirectsOrEchoBody(t *testing.T) {
	followed := false
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { followed = true }))
	defer target.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/secret" {
			http.Error(w, "internal secret body", http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	defer srv.Close()
	d := New(nil)
	d.allowLoopback = true

	ch := store.Channel{Kind: "slack", Config: json.RawMessage(`{"url":"` + srv.URL + `"}`)}
	err := d.deliver(context.Background(), ch, store.Entry{}, "x")
	if err == nil || followed {
		t.Fatalf("redirect should fail without being followed (err=%v followed=%v)", err, followed)
	}

	ch.Config = json.RawMessage(`{"url":"` + srv.URL + `/secret"}`)
	err = d.deliver(context.Background(), ch, store.Entry{}, "x")
	if err == nil || strings.Contains(err.Error(), "secret body") {
		t.Fatalf("error must carry the status only, got %v", err)
	}
	if err.Error() != "webhook returned 500" {
		t.Errorf("err = %q", err)
	}
}

func TestBuildMessageSanitizesHeaders(t *testing.T) {
	e := store.Entry{Severity: 3, Host: "fw1\r\nBcc: victim@example.com", AppName: "app\nX-Evil: 1"}
	subject := "[syslog-yard] " + severityName(e.Severity) + " — " + e.Host + " " + e.AppName
	msg := string(buildMessage("a@b.c\r\nBcc: x@y.z", []string{"ops@example.com"}, subject, "line1\nline2\r\n.\rend"))
	head, body, _ := strings.Cut(msg, "\r\n\r\n")
	for _, line := range strings.Split(head, "\r\n") {
		name, _, _ := strings.Cut(line, ":")
		switch name {
		case "From", "To", "Subject", "Date", "MIME-Version", "Content-Type":
		default:
			t.Errorf("unexpected header line %q", line)
		}
	}
	if !strings.Contains(head, "Subject: =?utf-8?q?") {
		t.Errorf("subject should be Q-encoded: %q", head)
	}
	if strings.Contains(strings.ReplaceAll(body, "\r\n", ""), "\r") || strings.Contains(strings.ReplaceAll(body, "\r\n", ""), "\n") {
		t.Errorf("body has bare CR/LF: %q", body)
	}
}

// fakeSMTP is a minimal SMTP server. With hang set it accepts and never
// speaks, to check the client's deadline.
func fakeSMTP(t *testing.T, hang bool, got chan<- string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		if hang {
			time.Sleep(5 * time.Second)
			return
		}
		r := bufio.NewReader(conn)
		write := func(s string) { conn.Write([]byte(s + "\r\n")) }
		write("220 fake ESMTP")
		var data strings.Builder
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			cmd := strings.ToUpper(strings.TrimSpace(line))
			switch {
			case strings.HasPrefix(cmd, "EHLO"), strings.HasPrefix(cmd, "HELO"):
				write("250 fake")
			case strings.HasPrefix(cmd, "MAIL"), strings.HasPrefix(cmd, "RCPT"):
				write("250 ok")
			case cmd == "DATA":
				write("354 go")
				for {
					l, err := r.ReadString('\n')
					if err != nil {
						return
					}
					if l == ".\r\n" {
						break
					}
					data.WriteString(l)
				}
				write("250 queued")
			case cmd == "QUIT":
				write("221 bye")
				got <- data.String()
				return
			default:
				write("500 what")
			}
		}
	}()
	return ln.Addr().String()
}

func smtpChannel(t *testing.T, addr string) store.Channel {
	host, port, _ := net.SplitHostPort(addr)
	cfg, _ := json.Marshal(map[string]any{"host": host, "port": json.Number(port), "from": "bucket@example.com", "to": []string{"ops@example.com"}, "tls": "none"})
	return store.Channel{Kind: "smtp", Config: cfg}
}

func TestSendSMTP(t *testing.T) {
	got := make(chan string, 1)
	addr := fakeSMTP(t, false, got)
	d := New(nil)
	e := store.Entry{Severity: 2, Host: "plc\r\nBcc: x@y.z", AppName: "modbus", Msg: "coil write"}
	if err := d.deliver(context.Background(), smtpChannel(t, addr), e, summary(e)); err != nil {
		t.Fatalf("smtp deliver: %v", err)
	}
	msg := <-got
	if head, _, _ := strings.Cut(msg, "\r\n\r\n"); strings.Contains(head, "\r\nBcc:") {
		t.Errorf("header injection reached the wire: %q", msg)
	}
	if !strings.Contains(msg, "coil write") {
		t.Errorf("body missing: %q", msg)
	}
}

func TestSendSMTPHonoursContext(t *testing.T) {
	addr := fakeSMTP(t, true, nil)
	d := New(nil)
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	start := time.Now()
	err := d.deliver(ctx, smtpChannel(t, addr), store.Entry{}, "x")
	if err == nil {
		t.Fatal("expected an error from a silent server")
	}
	if el := time.Since(start); el > 3*time.Second {
		t.Errorf("smtp send took %v; ctx deadline ignored", el)
	}
}
