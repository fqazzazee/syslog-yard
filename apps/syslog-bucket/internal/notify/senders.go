package notify

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/smtp"
	"net/url"
	"strings"
	"time"

	"github.com/syslog-yard/syslog-bucket/internal/store"
)

// smtpTimeout bounds a whole SMTP conversation (dial through QUIT).
const smtpTimeout = 20 * time.Second

// deliver routes an entry to a channel by kind.
func (d *Dispatcher) deliver(ctx context.Context, ch store.Channel, e store.Entry, text string) error {
	switch ch.Kind {
	case "webhook":
		return d.sendWebhook(ctx, ch, e, text)
	case "slack":
		return d.sendChat(ctx, ch, text)
	case "smtp":
		return d.sendSMTP(ctx, ch, e, text)
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
	e.Normalize() // [] / {} rather than null, matching the REST API
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

// post sends one webhook request. Errors carry only the status code or the
// transport failure — never the response body (which would reflect whatever
// an internal endpoint returned into the API and notification_log) and never
// the URL (Slack/Teams webhook URLs embed their secret token).
func (d *Dispatcher) post(ctx context.Context, rawURL, contentType string, body []byte) error {
	u, err := url.Parse(rawURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return errors.New("webhook url must be an http(s) URL")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, rawURL, bytes.NewReader(body))
	if err != nil {
		return errors.New("webhook url is invalid")
	}
	req.Header.Set("Content-Type", contentType)
	resp, err := d.client.Do(req)
	if err != nil {
		var uerr *url.Error
		if errors.As(err, &uerr) {
			err = uerr.Err
		}
		return fmt.Errorf("webhook request failed: %w", err)
	}
	defer resp.Body.Close()
	// Drain a little so the connection can be reused; the content is ignored.
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned %d", resp.StatusCode)
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
// "tls" dials implicit TLS (465); "none" sends in the clear (lab only). The
// whole conversation is bounded by smtpTimeout and aborted with ctx.
func (d *Dispatcher) sendSMTP(ctx context.Context, ch store.Channel, e store.Entry, text string) error {
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
	msg := buildMessage(cfg.From, cfg.To, subject, text+"\n\n"+e.Msg)
	addr := net.JoinHostPort(cfg.Host, fmt.Sprint(cfg.Port))

	var auth smtp.Auth
	if cfg.Username != "" {
		auth = smtp.PlainAuth("", cfg.Username, cfg.Password, cfg.Host)
	}

	ctx, cancel := context.WithTimeout(ctx, smtpTimeout)
	defer cancel()
	// Same outbound guard as webhooks: the channel config picks the host.
	conn, err := d.guard.Dialer(httpTimeout).DialContext(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	defer conn.Close()
	deadline, _ := ctx.Deadline()
	if err := conn.SetDeadline(deadline); err != nil {
		return err
	}
	// Cancelling ctx (shutdown, client gone) aborts a blocked read/write.
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()

	if cfg.TLS == "tls" {
		tc := tls.Client(conn, &tls.Config{ServerName: cfg.Host})
		if err := tc.HandshakeContext(ctx); err != nil {
			return err
		}
		conn = tc
	}
	return smtpConverse(conn, cfg.Host, cfg.TLS != "tls" && cfg.TLS != "none", auth, cfg.From, cfg.To, msg)
}

// smtpConverse runs the SMTP exchange on an established connection, upgrading
// with STARTTLS when asked and offered (as smtp.SendMail does).
func smtpConverse(conn net.Conn, host string, startTLS bool, auth smtp.Auth, from string, to []string, msg []byte) error {
	c, err := smtp.NewClient(conn, host)
	if err != nil {
		return err
	}
	defer c.Close()
	if err := c.Hello("localhost"); err != nil {
		return err
	}
	if startTLS {
		if ok, _ := c.Extension("STARTTLS"); ok {
			if err := c.StartTLS(&tls.Config{ServerName: host}); err != nil {
				return err
			}
		}
	}
	if auth != nil {
		if ok, _ := c.Extension("AUTH"); ok {
			if err := c.Auth(auth); err != nil {
				return err
			}
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

// headerValue strips CR/LF (and other control characters) so device-supplied
// text can never start a new header line.
func headerValue(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '\r' || r == '\n' || r == 0 {
			return ' '
		}
		if (r < 0x20 && r != '\t') || r == 0x7f {
			return -1
		}
		return r
	}, s)
}

func buildMessage(from string, to []string, subject, body string) []byte {
	rcpts := make([]string, len(to))
	for i, t := range to {
		rcpts[i] = headerValue(t)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "From: %s\r\n", headerValue(from))
	fmt.Fprintf(&b, "To: %s\r\n", strings.Join(rcpts, ", "))
	fmt.Fprintf(&b, "Subject: %s\r\n", mime.QEncoding.Encode("utf-8", headerValue(subject)))
	fmt.Fprintf(&b, "Date: %s\r\n", time.Now().Format(time.RFC1123Z))
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: text/plain; charset=UTF-8\r\n")
	b.WriteString("\r\n")
	// Normalize every line ending (CRLF, bare CR, bare LF) to CRLF.
	body = strings.ReplaceAll(body, "\r\n", "\n")
	body = strings.ReplaceAll(body, "\r", "\n")
	b.WriteString(strings.ReplaceAll(body, "\n", "\r\n"))
	return []byte(b.String())
}

func severityName(s int16) string {
	if int(s) >= 0 && int(s) < len(severityNames) {
		return severityNames[s]
	}
	return fmt.Sprint(s)
}
