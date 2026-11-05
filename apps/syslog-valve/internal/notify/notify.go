// Package notify delivers messages routed into a valve "notify" node to a
// webhook or Slack/Teams incoming webhook. It mirrors the
// live-tail tap: syslog-ng duplicates matched messages to a unix datagram
// socket tagged with the notify node's ident, and this dispatcher — running
// in the Go app, not syslog-ng — formats and POSTs them. Channel config lives
// in the graph node, so there is no separate store; delivery is best-effort
// and rate-limited per node so a chatty flow can't storm a chat channel.
//
// Each node gets its own worker and bounded queue, so the socket reader
// never waits on HTTP: a slow or dead endpoint only drops that node's
// messages (counted, not logged one by one).
//
// Email is intentionally not offered here: the valve graph is inspected,
// exported, and version-archived, which is the wrong place for an SMTP
// password. Use syslog-bucket's SMTP channel for email.
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/syslog-yard/shared/netguard"
	"github.com/syslog-yard/syslog-valve/internal/graph"
)

const (
	maxPayload  = 16 * 1024
	httpTimeout = 10 * time.Second
	logRing     = 100
	// queueSize is how many messages per node may wait for delivery; more
	// are dropped (and counted) rather than blocking the socket reader.
	queueSize = 32
	// DefaultRatePerMin caps deliveries for a notify node that leaves
	// ratePerMin unset (0). There is no unlimited setting.
	DefaultRatePerMin = 60
)

// EffectiveRate is the per-minute cap applied for a configured ratePerMin.
func EffectiveRate(configured int) int {
	if configured <= 0 {
		return DefaultRatePerMin
	}
	return configured
}

type targetConfig struct {
	name string
	kind string // webhook | slack
	url  string
	rate int
}

type job struct {
	text  string
	event map[string]string
}

// target is a notify node's delivery state, keyed by node ident. cfg,
// stats and pendingDrops are guarded by Dispatcher.mu.
type target struct {
	cfg          targetConfig
	lim          *limiter
	queue        chan job
	quit         chan struct{}
	stats        Stats
	pendingDrops int64
}

// Delivery is one recorded attempt, surfaced to the UI.
type Delivery struct {
	Seq    int64     `json:"seq"`
	Node   string    `json:"node"`
	Status string    `json:"status"` // ok | error | dropped
	Detail string    `json:"detail"`
	Time   time.Time `json:"time"`
}

// Stats are cumulative per-node counters since the valve started.
type Stats struct {
	Node       string `json:"node"`
	RatePerMin int    `json:"ratePerMin"`
	Sent       int64  `json:"sent"`
	Failed     int64  `json:"failed"`
	Dropped    int64  `json:"dropped"` // rate limited or queue full
}

type Dispatcher struct {
	client *http.Client

	mu      sync.Mutex
	targets map[string]*target
	seq     int64
	log     []Delivery
}

func New() *Dispatcher { return newDispatcher(false) }

func newDispatcher(allowLoopback bool) *Dispatcher {
	return &Dispatcher{
		client:  newClient(allowLoopback),
		targets: map[string]*target{},
	}
}

// newClient builds the delivery client on the suite's shared outbound
// guard (apps/shared/netguard): redirects are not followed, and loopback,
// link-local, unspecified, multicast and cloud-metadata destinations are
// refused at dial time, after DNS resolution. RFC 1918 ranges stay
// reachable (the usual webhook sink is a container on the same network).
// HTTP(S)_PROXY is used only with YARD_NOTIFY_PROXY=true, and then the
// target is checked before it is handed to the proxy.
func newClient(allowLoopback bool) *http.Client {
	g := netguard.New()
	g.AllowLoopback = allowLoopback
	return g.HTTPClient(httpTimeout)
}

// SetGraph refreshes the notify targets from an applied graph. Existing
// nodes keep their worker, queue, rate limiter and counters; removed nodes'
// workers stop.
func (d *Dispatcher) SetGraph(g *graph.Graph) {
	d.mu.Lock()
	defer d.mu.Unlock()
	next := map[string]*target{}
	for _, n := range g.Enabled().Nodes {
		if n.Type != graph.TypeNotify {
			continue
		}
		id := graph.Ident(n.ID)
		cfg := targetConfig{name: nodeName(n), kind: n.Config.NotifyKind, url: n.Config.URL, rate: EffectiveRate(n.Config.RatePerMin)}
		if t, ok := d.targets[id]; ok {
			t.cfg = cfg
			t.stats.Node, t.stats.RatePerMin = cfg.name, cfg.rate
			next[id] = t
			delete(d.targets, id)
			continue
		}
		t := &target{
			cfg:   cfg,
			lim:   newLimiter(),
			queue: make(chan job, queueSize),
			quit:  make(chan struct{}),
			stats: Stats{Node: cfg.name, RatePerMin: cfg.rate},
		}
		next[id] = t
		go d.worker(t)
	}
	for _, old := range d.targets {
		close(old.quit)
	}
	d.targets = next
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
		d.SetGraph(&graph.Graph{}) // stop the workers
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
// and queues it for the matching node's worker. It never blocks: over the
// rate limit or with a full queue the message is dropped and counted.
func (d *Dispatcher) handle(line string) {
	line = strings.TrimRight(line, "\n")
	parts := strings.SplitN(line, "\t", 6)
	if len(parts) < 6 {
		return
	}
	d.mu.Lock()
	t := d.targets[parts[0]]
	var rate int
	if t != nil {
		rate = t.cfg.rate
	}
	d.mu.Unlock()
	if t == nil {
		return // node removed between apply and delivery
	}
	if !t.lim.allow(rate) {
		d.drop(t)
		return
	}
	text := fmt.Sprintf("[%s] %s %s: %s", parts[4], parts[2], parts[3], parts[5])
	ev := map[string]string{"time": parts[1], "host": parts[2], "program": parts[3], "level": parts[4], "message": parts[5]}
	select {
	case t.queue <- job{text: text, event: ev}:
	default:
		d.drop(t)
	}
}

func (d *Dispatcher) drop(t *target) {
	d.mu.Lock()
	t.stats.Dropped++
	t.pendingDrops++
	d.mu.Unlock()
}

func (d *Dispatcher) worker(t *target) {
	for {
		select {
		case <-t.quit:
			return
		case j := <-t.queue:
			d.mu.Lock()
			cfg := t.cfg
			dropped := t.pendingDrops
			t.pendingDrops = 0
			d.mu.Unlock()
			if dropped > 0 {
				d.record(cfg.name, "dropped", fmt.Sprintf("%d message(s) dropped since the previous delivery (limit %d/min, queue %d)", dropped, cfg.rate, queueSize))
			}
			err := d.send(context.Background(), cfg, j.text, j.event)
			d.mu.Lock()
			if err != nil {
				t.stats.Failed++
			} else {
				t.stats.Sent++
			}
			d.mu.Unlock()
			if err != nil {
				d.record(cfg.name, "error", err.Error())
			} else {
				d.record(cfg.name, "ok", "")
			}
		}
	}
}

// TestSend delivers a synthetic message to a channel config, for the UI's
// test button (before the graph is applied). It goes through the same
// guarded client as real deliveries.
func (d *Dispatcher) TestSend(ctx context.Context, kind, rawURL string) error {
	if kind != "webhook" && kind != "slack" {
		return fmt.Errorf("kind must be webhook or slack")
	}
	if err := graph.CheckNotifyURL(rawURL); err != nil {
		return err
	}
	text := "Test notification from syslog-valve — this channel is wired up."
	ev := map[string]string{"host": "syslog-valve", "program": "notify-test", "level": "notice", "message": text}
	return d.send(ctx, targetConfig{kind: kind, url: rawURL}, text, ev)
}

// slackEscape applies Slack's message formatting escapes so log content
// can't produce mentions or links such as <!channel>.
var slackEscape = strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;")

func (d *Dispatcher) send(ctx context.Context, t targetConfig, text string, event map[string]string) error {
	if strings.TrimSpace(t.url) == "" {
		return fmt.Errorf("channel has no URL")
	}
	var body []byte
	var err error
	switch t.kind {
	case "slack":
		body, err = compactJSON(map[string]string{"text": slackEscape.Replace(text)})
	default: // webhook
		body, err = compactJSON(map[string]any{"source": "syslog-valve", "text": text, "event": event})
	}
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("invalid URL")
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := d.client.Do(req)
	if err != nil {
		// url.Error repeats the full URL, and webhook URLs embed secrets.
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return fmt.Errorf("delivery failed: %w", err)
	}
	// Drain a little so the connection can be reused; never echo the
	// body back to the API or logs.
	io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("endpoint returned HTTP %d", resp.StatusCode)
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

// Stats returns per-node counters for the current targets, keyed by node
// ident.
func (d *Dispatcher) Stats() map[string]Stats {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make(map[string]Stats, len(d.targets))
	for id, t := range d.targets {
		out[id] = t.stats
	}
	return out
}

// Targets returns the idents of the configured notify nodes, sorted.
func (d *Dispatcher) Targets() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make([]string, 0, len(d.targets))
	for id := range d.targets {
		out = append(out, id)
	}
	sort.Strings(out)
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
