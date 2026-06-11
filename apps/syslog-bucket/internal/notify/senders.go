package notify

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/smtp"
	"strings"
	"time"

	"github.com/syslog-yard/syslog-bucket/internal/store"
)

// deliver routes an entry to a channel by kind.
func (d *Dispatcher) deliver(ctx context.Context, ch store.Channel, e store.Entry, text string) error {
	switch ch.Kind {
	case "webhook":
		return d.sendWebhook(ctx, ch, e, text)
	case "slack":
		return d.sendChat(ctx, ch, text)
	case "smtp":
		return d.sendSMTP(ch, e, text)
	default:
		return fmt.Errorf("unknown channel kind %q", ch.Kind)
	}
}

type webhookConfig struct {
	URL string `json:"url"`
}

// sendWebhook POSTs a structured JSON payload (the full entry plus a rendered
// text line) to a generic endpoint.
func (d *Dispatcher) sendWebhook(ctx context.Context, ch store.Channel, e store.Entry, text string) error {
	var cfg webhookConfig
	if err := json.Unmarshal(ch.Config, &cfg); err != nil || strings.TrimSpace(cfg.URL) == "" {
		return fmt.Errorf("webhook channel needs a url")
	}
	body, err := compactJSON(map[string]any{
		"channel": ch.Name,
		"text":    text,
		"entry":   e,
	})
	if err != nil {
		return err
	}
	return d.post(ctx, cfg.URL, "application/json", body)
}

// sendChat POSTs a Slack/Teams-compatible {"text": ...} payload to an
// incoming-webhook URL.
func (d *Dispatcher) sendChat(ctx context.Context, ch store.Channel, text string) error {
	var cfg webhookConfig
	if err := json.Unmarshal(ch.Config, &cfg); err != nil || strings.TrimSpace(cfg.URL) == "" {
		return fmt.Errorf("chat channel needs a url")
	}
	body, err := compactJSON(map[string]string{"text": text})
	if err != nil {
		return err
	}
	return d.post(ctx, cfg.URL, "application/json", body)
}

func (d *Dispatcher) post(ctx context.Context, url, contentType string, body []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(string(body)))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", contentType)
	resp, err := d.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 200))
		return fmt.Errorf("webhook returned %d: %s", resp.StatusCode, strings.TrimSpace(string(snippet)))
	}
	return nil
}

type smtpConfig struct {
	Host     string   `json:"host"`
	Port     int      `json:"port"`
	Username string   `json:"username"`
	Password string   `json:"password"`
	From     string   `json:"from"`
	To       []string `json:"to"`
	TLS      string   `json:"tls"` // "starttls" (default) | "tls" | "none"
}

// sendSMTP composes and sends an email. STARTTLS (587) is the default;
// "tls" dials implicit TLS (465); "none" sends in the clear (lab only).
func (d *Dispatcher) sendSMTP(ch store.Channel, e store.Entry, text string) error {
	var cfg smtpConfig
	if err := json.Unmarshal(ch.Config, &cfg); err != nil {
		return err
	}
	if cfg.Host == "" || cfg.From == "" || len(cfg.To) == 0 {
		return fmt.Errorf("smtp channel needs host, from, and at least one to")
	}
	if cfg.Port == 0 {
		cfg.Port = 587
	}
	subject := fmt.Sprintf("[syslog-yard] %s — %s %s", strings.TrimSpace(severityName(e.Severity)), e.Host, e.AppName)
	msg := buildMessage(cfg.From, cfg.To, subject, text+"\r\n\r\n"+e.Msg)
	addr := net.JoinHostPort(cfg.Host, fmt.Sprint(cfg.Port))

	var auth smtp.Auth
	if cfg.Username != "" {
		auth = smtp.PlainAuth("", cfg.Username, cfg.Password, cfg.Host)
	}

	if cfg.TLS == "tls" {
		return sendImplicitTLS(addr, cfg.Host, auth, cfg.From, cfg.To, msg)
	}
	// STARTTLS (when offered) and plain are both handled by SendMail.
	return smtp.SendMail(addr, auth, cfg.From, cfg.To, msg)
}

// sendImplicitTLS handles port-465 style servers that expect TLS from the
// first byte (SendMail can't do this).
func sendImplicitTLS(addr, host string, auth smtp.Auth, from string, to []string, msg []byte) error {
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: httpTimeout}, "tcp", addr, &tls.Config{ServerName: host})
	if err != nil {
		return err
	}
	c, err := smtp.NewClient(conn, host)
	if err != nil {
		return err
	}
	defer c.Close()
	if auth != nil {
		if err := c.Auth(auth); err != nil {
			return err
		}
	}
	if err := c.Mail(from); err != nil {
		return err
	}
	for _, rcpt := range to {
		if err := c.Rcpt(rcpt); err != nil {
			return err
		}
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write(msg); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return c.Quit()
}

func buildMessage(from string, to []string, subject, body string) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "From: %s\r\n", from)
	fmt.Fprintf(&b, "To: %s\r\n", strings.Join(to, ", "))
	fmt.Fprintf(&b, "Subject: %s\r\n", subject)
	fmt.Fprintf(&b, "Date: %s\r\n", time.Now().Format(time.RFC1123Z))
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: text/plain; charset=UTF-8\r\n")
	b.WriteString("\r\n")
	b.WriteString(strings.ReplaceAll(body, "\n", "\r\n"))
	return []byte(b.String())
}

func severityName(s int16) string {
	if int(s) >= 0 && int(s) < len(severityNames) {
		return severityNames[s]
	}
	return fmt.Sprint(s)
}
