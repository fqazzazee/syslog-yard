// Package notify delivers messages routed into a valve "notify" node to a
// webhook or Slack/Teams incoming webhook (S9 valve notify). It mirrors the
// live-tail tap: syslog-ng duplicates matched messages to a unix datagram
// socket tagged with the notify node's ident, and this dispatcher — running
// in the Go app, not syslog-ng — formats and POSTs them. Channel config lives
// in the graph node, so there is no separate store; delivery is best-effort
// and rate-limited per node so a chatty flow can't storm a chat channel.
//
// Email is intentionally not offered here: the valve graph is inspected,
// exported, and version-archived, which is the wrong place for an SMTP
// password. Use syslog-bucket's SMTP channel for email.
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/syslog-yard/syslog-valve/internal/graph"
)

const (
	maxPayload  = 16 * 1024
	httpTimeout = 10 * time.Second
	logRing     = 100
)

// target is a notify node's delivery config, keyed by node ident.
type target struct {
	name string
	kind string // webhook | slack
	url  string
	rate int
	lim  *limiter
}

// Delivery is one recorded attempt, surfaced to the UI.
type Delivery struct {
	Seq    int64     `json:"seq"`
	Node   string    `json:"node"`
	Status string    `json:"status"` // ok | error | dropped
	Detail string    `json:"detail"`
	Time   time.Time `json:"time"`
}

type Dispatcher struct {
	client *http.Client

	mu      sync.Mutex
	targets map[string]*target
	seq     int64
	log     []Delivery
}

func New() *Dispatcher {
	return &Dispatcher{
		client:  &http.Client{Timeout: httpTimeout},
		targets: map[string]*target{},
	}
}

// SetGraph refreshes the notify targets from an applied graph, preserving the
// per-node rate limiter across reapplies.
func (d *Dispatcher) SetGraph(g *graph.Graph) {
	next := map[string]*target{}
	for _, n := range g.Nodes {
		if n.Type != graph.TypeNotify {
			continue
		}
		id := graph.Ident(n.ID)
		t := &target{name: nodeName(n), kind: n.Config.NotifyKind, url: n.Config.URL, rate: n.Config.RatePerMin}
		d.mu.Lock()
		if prev, ok := d.targets[id]; ok {
			t.lim = prev.lim
		}
		d.mu.Unlock()
		if t.lim == nil {
			t.lim = newLimiter()
		}
		next[id] = t
	}
	d.mu.Lock()
	d.targets = next
	d.mu.Unlock()
}

// Listen binds the notify datagram socket and delivers until ctx is done. It
// mirrors tap.Listen so the socket exists before syslog-ng starts.
func (d *Dispatcher) Listen(ctx context.Context, path string) error {
	os.Remove(path)
	conn, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: path, Net: "unixgram"})
	if err != nil {
		return err
	}
	go func() {
		<-ctx.Done()
		conn.Close()
		os.Remove(path)
	}()
	go func() {
		buf := make([]byte, maxPayload)
		for {
			n, err := conn.Read(buf)
			if err != nil {
				return // closed on shutdown
			}
			d.handle(string(buf[:n]))
		}
	}()
	return nil
}

// handle parses one datagram (ident\tisodate\thost\tprogram\tlevel\tmessage)
// and delivers it to the matching node's channel.
func (d *Dispatcher) handle(line string) {
	line = strings.TrimRight(line, "\n")
	parts := strings.SplitN(line, "\t", 6)
	if len(parts) < 6 {
		return
	}
	ident := parts[0]
	d.mu.Lock()
	t := d.targets[ident]
	d.mu.Unlock()
	if t == nil {
		return // node removed between apply and delivery
	}
	if !t.lim.allow(t.rate) {
		d.record(t.name, "dropped", "rate limited")
		return
	}
	text := fmt.Sprintf("[%s] %s %s: %s", parts[4], parts[2], parts[3], parts[5])
	ev := map[string]string{"time": parts[1], "host": parts[2], "program": parts[3], "level": parts[4], "message": parts[5]}
	if err := d.send(context.Background(), t, text, ev); err != nil {
		d.record(t.name, "error", err.Error())
	} else {
		d.record(t.name, "ok", "")
	}
}

// TestSend delivers a synthetic message to a channel config, for the UI's
// test button (before the graph is applied).
func (d *Dispatcher) TestSend(ctx context.Context, kind, url string) error {
	t := &target{kind: kind, url: url}
	text := "Test notification from syslog-valve — this channel is wired up."
	ev := map[string]string{"host": "syslog-valve", "program": "notify-test", "level": "notice", "message": text}
	return d.send(ctx, t, text, ev)
}

func (d *Dispatcher) send(ctx context.Context, t *target, text string, event map[string]string) error {
	if strings.TrimSpace(t.url) == "" {
		return fmt.Errorf("channel has no URL")
	}
	var body []byte
	var err error
	switch t.kind {
	case "slack":
		body, err = compactJSON(map[string]string{"text": text})
	default: // webhook
		body, err = compactJSON(map[string]any{"source": "syslog-valve", "text": text, "event": event})
	}
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := d.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 200))
		return fmt.Errorf("endpoint returned %d: %s", resp.StatusCode, strings.TrimSpace(string(snippet)))
	}
	return nil
}

func (d *Dispatcher) record(node, status, detail string) {
	if status == "error" {
		slog.Warn("notify delivery failed", "node", node, "detail", detail)
	}
	d.mu.Lock()
	d.seq++
	d.log = append(d.log, Delivery{Seq: d.seq, Node: node, Status: status, Detail: detail, Time: time.Now()})
	if len(d.log) > logRing {
		d.log = d.log[len(d.log)-logRing:]
	}
	d.mu.Unlock()
}

// Recent returns the latest deliveries, newest first.
func (d *Dispatcher) Recent() []Delivery {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make([]Delivery, len(d.log))
	for i, dlv := range d.log {
		out[len(d.log)-1-i] = dlv
	}
	return out
}

func nodeName(n graph.Node) string {
	if n.Name != "" {
		return n.Name
	}
	return n.ID
}

func compactJSON(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}
