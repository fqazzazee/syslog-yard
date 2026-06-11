// Package notify delivers entries to notification channels (S9). The rule
// engine queues a notify on an entry at ingest; after the entry is stored the
// ingest batcher hands the batch here, and a small worker pool formats and
// delivers each to its channel (generic webhook, Slack/Teams webhook, or
// SMTP email). Delivery is best-effort and off the ingest path: a slow or
// failing channel never blocks ingestion. Per-channel rate limiting guards
// against alert storms, and every attempt is recorded in notification_log.
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/syslog-yard/syslog-bucket/internal/store"
)

const (
	workers        = 4
	queueDepth     = 4096
	reloadInterval = 30 * time.Second
	pruneInterval  = time.Hour
	logRetention   = 7 * 24 * time.Hour
	httpTimeout    = 10 * time.Second
)

var severityNames = []string{"emerg", "alert", "crit", "err", "warning", "notice", "info", "debug"}

// job is one queued delivery.
type job struct {
	entry     store.Entry
	channelID int64
	ruleID    int64
}

type Dispatcher struct {
	st     *store.Store
	client *http.Client
	queue  chan job

	mu       sync.RWMutex
	channels map[int64]store.Channel
	limiters map[int64]*limiter
}

func New(st *store.Store) *Dispatcher {
	return &Dispatcher{
		st:       st,
		client:   &http.Client{Timeout: httpTimeout},
		queue:    make(chan job, queueDepth),
		channels: map[int64]store.Channel{},
		limiters: map[int64]*limiter{},
	}
}

// Reload refreshes the channel snapshot from the database. The API calls it
// after a channel changes; Run also calls it periodically.
func (d *Dispatcher) Reload(ctx context.Context) error {
	list, err := d.st.ListChannels(ctx)
	if err != nil {
		return err
	}
	m := make(map[int64]store.Channel, len(list))
	for _, c := range list {
		m[c.ID] = c
	}
	d.mu.Lock()
	d.channels = m
	// Keep a limiter per channel; drop limiters for deleted channels.
	for id := range d.limiters {
		if _, ok := m[id]; !ok {
			delete(d.limiters, id)
		}
	}
	d.mu.Unlock()
	return nil
}

// Run starts the worker pool plus periodic reload and log pruning until ctx
// is cancelled.
func (d *Dispatcher) Run(ctx context.Context) {
	for i := 0; i < workers; i++ {
		go d.worker(ctx)
	}
	reload := time.NewTicker(reloadInterval)
	prune := time.NewTicker(pruneInterval)
	defer reload.Stop()
	defer prune.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-reload.C:
			if err := d.Reload(ctx); err != nil && ctx.Err() == nil {
				slog.Error("notify: reload channels", "error", err)
			}
		case <-prune.C:
			if err := d.st.PruneDeliveries(context.WithoutCancel(ctx), logRetention); err != nil {
				slog.Error("notify: prune log", "error", err)
			}
		}
	}
}

// Dispatch enqueues deliveries for entries a notify rule matched. Non-blocking:
// if the queue is saturated the delivery is dropped and logged, never stalling
// ingest.
func (d *Dispatcher) Dispatch(entries []store.Entry) {
	for _, e := range entries {
		for _, n := range e.Notifies {
			select {
			case d.queue <- job{entry: e, channelID: n.ChannelID, ruleID: n.RuleID}:
			default:
				slog.Warn("notify: queue full, dropping", "channel", n.ChannelID, "entry", e.ID)
				id := e.ID
				d.log(store.Delivery{ChannelID: n.ChannelID, EntryID: &id, RuleID: ptr(n.RuleID), Status: "dropped", Detail: "dispatch queue full"})
			}
		}
	}
}

func (d *Dispatcher) worker(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case j := <-d.queue:
			d.handle(ctx, j)
		}
	}
}

func (d *Dispatcher) handle(ctx context.Context, j job) {
	d.mu.RLock()
	ch, ok := d.channels[j.channelID]
	lim := d.limiters[j.channelID]
	if ok && lim == nil {
		lim = newLimiter()
		d.limiters[j.channelID] = lim
	}
	d.mu.RUnlock()

	rec := store.Delivery{ChannelID: j.channelID, EntryID: &j.entry.ID, RuleID: ptr(j.ruleID)}
	if !ok || !ch.Enabled {
		// Channel vanished or was disabled between queue and delivery; skip
		// quietly without a log row.
		return
	}
	if lim != nil && !lim.allow(ch.RatePerMin) {
		rec.Status, rec.Detail = "dropped", "rate limited"
		d.log(rec)
		return
	}
	if err := d.deliver(ctx, ch, j.entry, summary(j.entry)); err != nil {
		rec.Status, rec.Detail = "error", err.Error()
	} else {
		rec.Status = "ok"
	}
	d.log(rec)
}

// TestSend delivers a synthetic entry to a channel synchronously, bypassing
// the rate limiter — backs the UI's "send test" button.
func (d *Dispatcher) TestSend(ctx context.Context, ch store.Channel) error {
	e := store.Entry{
		ReceivedAt: time.Now(),
		Severity:   4,
		Host:       "syslog-yard",
		AppName:    "notify-test",
		Msg:        "Test notification from syslog-bucket — your channel is wired up.",
	}
	return d.deliver(ctx, ch, e, "Test notification from syslog-bucket — your channel is wired up.")
}

func (d *Dispatcher) log(rec store.Delivery) {
	if err := d.st.LogDelivery(context.Background(), rec); err != nil {
		slog.Error("notify: log delivery", "error", err)
	}
}

// summary renders a one-line human description of an entry for chat/email.
func summary(e store.Entry) string {
	sev := fmt.Sprint(e.Severity)
	if int(e.Severity) >= 0 && int(e.Severity) < len(severityNames) {
		sev = severityNames[e.Severity]
	}
	msg := e.Msg
	if len(msg) > 300 {
		msg = msg[:300] + "…"
	}
	s := fmt.Sprintf("[%s] %s %s: %s", sev, e.Host, e.AppName, msg)
	if len(e.Mitre) > 0 {
		s += " · MITRE " + joinComma(e.Mitre)
	}
	return s
}

func ptr(v int64) *int64 {
	if v == 0 {
		return nil
	}
	return &v
}

func joinComma(xs []string) string {
	out := ""
	for i, x := range xs {
		if i > 0 {
			out += ", "
		}
		out += x
	}
	return out
}

// marshalIndent is a tiny helper kept here so webhook payloads are compact.
func compactJSON(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}
