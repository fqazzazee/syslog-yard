// Package notify delivers entries to notification channels. The rule
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
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/syslog-yard/shared/netguard"
	"github.com/syslog-yard/syslog-bucket/internal/store"
)

const (
	workers        = 4
	queueDepth     = 4096
	reloadInterval = 30 * time.Second
	pruneInterval  = time.Hour
	logRetention   = 7 * 24 * time.Hour
	dropFlushEvery = 10 * time.Second
	httpTimeout    = 10 * time.Second
	testTimeout    = 25 * time.Second // bounds the UI's synchronous "send test"
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

	// guard is the shared outbound guard (apps/shared/netguard) for every
	// channel kind: webhook and Slack/Teams through client, SMTP through
	// guard.Dialer. Tests set guard.AllowLoopback to reach httptest servers.
	guard *netguard.Guard

	mu       sync.RWMutex
	channels map[int64]store.Channel
	limiters map[int64]*limiter

	// Queue-full drops are counted here and written to notification_log as
	// one aggregate row per (channel, rule) every dropFlushEvery, so a storm
	// never turns into an INSERT per dropped delivery on the ingest goroutine.
	dropMu sync.Mutex
	drops  map[dropKey]int

	// Shutdown plumbing: workers deliver under deliverCtx (not Run's ctx) so
	// queued jobs can still go out after the process starts stopping;
	// Shutdown closes the queue and, past its deadline, cancels deliverCtx
	// and sets abandon so leftover jobs are counted as dropped.
	deliverCtx    context.Context
	cancelDeliver context.CancelFunc
	closeMu       sync.RWMutex
	closed        bool
	abandon       atomic.Bool
	workerWG      sync.WaitGroup
	started       bool // workers running; guarded by closeMu
}

type dropKey struct{ channelID, ruleID int64 }

func New(st *store.Store) *Dispatcher {
	d := &Dispatcher{
		st:       st,
		queue:    make(chan job, queueDepth),
		channels: map[int64]store.Channel{},
		limiters: map[int64]*limiter{},
		drops:    map[dropKey]int{},
	}
	d.deliverCtx, d.cancelDeliver = context.WithCancel(context.Background())
	d.guard = netguard.New()
	d.client = d.guard.HTTPClient(httpTimeout)
	return d
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
	// Keep a limiter per channel: create one for each new channel here, under
	// the write lock, and drop limiters for deleted channels.
	for id := range m {
		if d.limiters[id] == nil {
			d.limiters[id] = newLimiter()
		}
	}
	for id := range d.limiters {
		if _, ok := m[id]; !ok {
			delete(d.limiters, id)
		}
	}
	d.mu.Unlock()
	return nil
}

// Run starts the worker pool plus periodic reload and log pruning until ctx
// is cancelled. The workers outlive ctx: they keep draining the queue until
// Shutdown.
func (d *Dispatcher) Run(ctx context.Context) {
	d.closeMu.Lock()
	if !d.closed {
		d.startWorkersLocked()
	}
	d.closeMu.Unlock()
	reload := time.NewTicker(reloadInterval)
	prune := time.NewTicker(pruneInterval)
	dropFlush := time.NewTicker(dropFlushEvery)
	defer reload.Stop()
	defer prune.Stop()
	defer dropFlush.Stop()
	for {
		select {
		case <-ctx.Done():
			d.flushDrops()
			return
		case <-dropFlush.C:
			d.flushDrops()
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
// if the queue is saturated the delivery is dropped and counted (flushed to
// the log periodically by flushDrops), never stalling ingest.
func (d *Dispatcher) Dispatch(entries []store.Entry) {
	d.closeMu.RLock()
	defer d.closeMu.RUnlock()
	for _, e := range entries {
		if e.Suppressed {
			// The engine already drops a suppressed entry's notifications
			// (suppress beats notify); this keeps the rule in one more place.
			continue
		}
		for _, n := range e.Notifies {
			if d.closed {
				d.countDrop(n.ChannelID, n.RuleID)
				continue
			}
			select {
			case d.queue <- job{entry: e, channelID: n.ChannelID, ruleID: n.RuleID}:
			default:
				d.countDrop(n.ChannelID, n.RuleID)
			}
		}
	}
}

func (d *Dispatcher) countDrop(channelID, ruleID int64) {
	d.dropMu.Lock()
	d.drops[dropKey{channelID, ruleID}]++
	d.dropMu.Unlock()
}

// flushDrops writes one notification_log row per (channel, rule) summarising
// the deliveries dropped since the last flush.
func (d *Dispatcher) flushDrops() {
	d.dropMu.Lock()
	drops := d.drops
	d.drops = map[dropKey]int{}
	d.dropMu.Unlock()
	for k, n := range drops {
		slog.Warn("notify: queue full, dropped deliveries", "channel", k.channelID, "rule", k.ruleID, "count", n)
		d.log(store.Delivery{ChannelID: k.channelID, RuleID: ptr(k.ruleID), Status: "dropped",
			Detail: fmt.Sprintf("dispatch queue full: %d deliveries dropped", n)})
	}
}

// startWorkersLocked starts the pool once; the caller holds closeMu, which
// orders every workerWG.Add before Shutdown's Wait.
func (d *Dispatcher) startWorkersLocked() {
	if d.started {
		return
	}
	d.started = true
	for i := 0; i < workers; i++ {
		d.workerWG.Add(1)
		go d.worker()
	}
}

func (d *Dispatcher) worker() {
	defer d.workerWG.Done()
	for j := range d.queue {
		if d.abandon.Load() {
			d.countDrop(j.channelID, j.ruleID)
			continue
		}
		d.handle(d.deliverCtx, j)
	}
}

// Shutdown stops accepting deliveries and gives the workers up to timeout to
// send what is already queued. Past that, in-flight sends are cancelled and
// the remainder is counted as dropped. Call it after ingest has stopped (no
// more Dispatch calls are expected; late ones are counted as dropped).
func (d *Dispatcher) Shutdown(timeout time.Duration) {
	d.closeMu.Lock()
	if d.closed {
		d.closeMu.Unlock()
		return
	}
	d.startWorkersLocked() // Run may not have started them yet
	d.closed = true
	close(d.queue)
	d.closeMu.Unlock()

	done := make(chan struct{})
	go func() {
		d.workerWG.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(timeout):
		slog.Warn("notify: shutdown deadline passed, abandoning queued deliveries", "queued", len(d.queue))
		d.abandon.Store(true)
		d.cancelDeliver()
		select {
		case <-done:
		case <-time.After(time.Second):
		}
	}
	d.cancelDeliver()
	d.flushDrops()
}

// channel returns the channel snapshot and its limiter. Reload normally
// creates the limiter; if a channel somehow lacks one, it is created under the
// write lock (re-checked) so concurrent workers share a single limiter.
func (d *Dispatcher) channel(id int64) (store.Channel, *limiter, bool) {
	d.mu.RLock()
	ch, ok := d.channels[id]
	lim := d.limiters[id]
	d.mu.RUnlock()
	if !ok || lim != nil {
		return ch, lim, ok
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	ch, ok = d.channels[id]
	if !ok {
		return ch, nil, false
	}
	if lim = d.limiters[id]; lim == nil {
		lim = newLimiter()
		d.limiters[id] = lim
	}
	return ch, lim, true
}

func (d *Dispatcher) handle(ctx context.Context, j job) {
	ch, lim, ok := d.channel(j.channelID)

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
	ctx, cancel := context.WithTimeout(ctx, testTimeout)
	defer cancel()
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
	if d.st == nil {
		return
	}
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
	msg := truncateRunes(e.Msg, 300)
	// Host/app are device-supplied: keep the summary on one line.
	s := fmt.Sprintf("[%s] %s %s: %s", sev, headerValue(e.Host), headerValue(e.AppName), msg)
	if len(e.Mitre) > 0 {
		s += " · MITRE " + joinComma(e.Mitre)
	}
	return s
}

// truncateRunes shortens s to at most max bytes without splitting a UTF-8
// sequence, appending an ellipsis when it cut anything.
func truncateRunes(s string, max int) string {
	if len(s) <= max {
		return s
	}
	cut := max
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "…"
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
