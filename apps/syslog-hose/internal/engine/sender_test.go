package engine

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	crand "crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"math/big"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// readFrame reads one RFC 6587 octet-counted frame.
func readFrame(br *bufio.Reader) (string, error) {
	n, err := br.ReadString(' ')
	if err != nil {
		return "", err
	}
	size, err := strconv.Atoi(strings.TrimSpace(n))
	if err != nil {
		return "", err
	}
	buf := make([]byte, size)
	if _, err := io.ReadFull(br, buf); err != nil {
		return "", err
	}
	return string(buf), nil
}

// selfSignedTLS returns a server config with a throwaway certificate.
func selfSignedTLS(t *testing.T) *tls.Config {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), crand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(crand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
}

// closingServer accepts connections forever and hangs up on each one after
// reading perConn frames, forwarding every frame it read. tlsCfg != nil
// serves TLS; accepts counts connections.
func closingServer(t *testing.T, perConn int, tlsCfg *tls.Config) (port int, got <-chan string, accepts *atomic.Int64) {
	t.Helper()
	var l net.Listener
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	port = l.Addr().(*net.TCPAddr).Port
	if tlsCfg != nil {
		l = tls.NewListener(l, tlsCfg)
	}
	ch := make(chan string, 1000)
	accepts = new(atomic.Int64)
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			accepts.Add(1)
			br := bufio.NewReader(c)
			for i := 0; i < perConn; i++ {
				msg, err := readFrame(br)
				if err != nil {
					break
				}
				ch <- msg
			}
			c.Close()
		}
	}()
	return port, ch, accepts
}

// A receiver that closes connections must not cost messages: the sender
// notices the hang-up (FIN, or TLS close_notify) before writing and
// reconnects, so every Send that reported success arrives.
func TestStreamSenderSurvivesPeerClose(t *testing.T) {
	for _, transport := range []string{"tcp", "tls"} {
		t.Run(transport, func(t *testing.T) {
			var cfg *tls.Config
			if transport == "tls" {
				cfg = selfSignedTLS(t)
			}
			port, got, accepts := closingServer(t, 4, cfg)
			s, err := NewSender(context.Background(), transport, "127.0.0.1", port, true)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()

			const total = 40
			for i := 0; i < total; i++ {
				if err := s.Send(fmt.Sprintf("msg-%d", i)); err != nil {
					t.Fatalf("send %d: %v", i, err)
				}
				time.Sleep(20 * time.Millisecond) // let the server's hang-up arrive
			}
			timeout := time.After(3 * time.Second)
			for i := 0; i < total; i++ {
				select {
				case msg := <-got:
					if want := fmt.Sprintf("msg-%d", i); msg != want {
						t.Fatalf("got %q, want %q", msg, want)
					}
				case <-timeout:
					t.Fatalf("only %d/%d messages arrived", i, total)
				}
			}
			if n := accepts.Load(); n != total/4 {
				t.Fatalf("expected %d connections, got %d", total/4, n)
			}
		})
	}
}

// Post-handshake TLS traffic (session tickets) must not be mistaken for a
// hang-up: one connection carries everything.
func TestTLSSenderNoSpuriousReconnect(t *testing.T) {
	port, got, accepts := closingServer(t, 1000, selfSignedTLS(t))
	s, err := NewSender(context.Background(), "tls", "127.0.0.1", port, true)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	for i := 0; i < 50; i++ {
		if err := s.Send("hello"); err != nil {
			t.Fatal(err)
		}
		if i%10 == 0 {
			time.Sleep(10 * time.Millisecond)
		}
	}
	for i := 0; i < 50; i++ {
		select {
		case <-got:
		case <-time.After(3 * time.Second):
			t.Fatalf("only %d/50 arrived", i)
		}
	}
	if n := accepts.Load(); n != 1 {
		t.Fatalf("expected a single connection, got %d", n)
	}
}

// A failed write is retried once on a fresh connection with the same frame.
func TestStreamSenderResendsAfterWriteError(t *testing.T) {
	port, got, _ := closingServer(t, 100, nil)
	snd, err := NewSender(context.Background(), "tcp", "127.0.0.1", port, false)
	if err != nil {
		t.Fatal(err)
	}
	s := snd.(*streamSender)
	defer s.Close()
	// a connection whose writes fail and that a peek can't see through
	dead, other := net.Pipe()
	other.Close()
	s.conn, s.unwatch = dead, func() bool { return true }

	if err := s.Send("resent"); err != nil {
		t.Fatalf("send should have recovered on a new connection: %v", err)
	}
	select {
	case msg := <-got:
		if msg != "resent" {
			t.Fatalf("got %q", msg)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("resent frame never arrived")
	}
}

func TestStreamSenderBacksOffWhenDown(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close() // nothing listens here now

	snd, _ := NewSender(context.Background(), "tcp", "127.0.0.1", port, false)
	s := snd.(*streamSender)
	if err := s.Send("x"); err == nil {
		t.Fatal("send to a closed port succeeded")
	}
	err = s.Send("y")
	if err == nil || !strings.Contains(err.Error(), "retrying in") {
		t.Fatalf("second send should fail fast during backoff, got %v", err)
	}
	// delays grow and stay capped
	var last time.Duration
	for i := 0; i < 20; i++ {
		s.backoff()
		d := time.Until(s.nextRetry)
		if d > backoffMax {
			t.Fatalf("backoff %s exceeds cap", d)
		}
		last = d
	}
	if last < backoffMax/2-50*time.Millisecond {
		t.Fatalf("backoff did not grow towards the cap: %s", last)
	}
}

// Cancelling the context aborts a write blocked on a receiver that stopped
// reading, so stopping a job never waits out the write timeout.
func TestStreamSenderCancelAbortsBlockedWrite(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		c, err := l.Accept()
		if err == nil {
			defer c.Close()
			time.Sleep(5 * time.Second) // never read
		}
	}()
	ctx, cancel := context.WithCancel(context.Background())
	s, _ := NewSender(ctx, "tcp", "127.0.0.1", l.Addr().(*net.TCPAddr).Port, false)
	defer s.Close()
	big := strings.Repeat("x", 1<<20)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for ctx.Err() == nil {
			s.Send(big)
		}
	}()
	time.Sleep(300 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("blocked write was not aborted by cancel")
	}
}
