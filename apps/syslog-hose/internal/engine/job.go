package engine

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"math/rand"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/syslog-yard/syslog-hose/internal/preset"
)

// JobConfig is the persisted definition of a generator stream.
type JobConfig struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Preset      string `json:"preset"`
	Host        string `json:"host"`
	Port        int    `json:"port"`
	Transport   string `json:"transport"`   // udp | tcp | tls
	TLSInsecure bool   `json:"tlsInsecure"` // skip cert verification (labs)
	// TLSCA is PEM: a CA bundle or the receiver's own certificate (pinned)
	// to verify it against instead of the system roots.
	TLSCA string `json:"tlsCA,omitempty"`
	// TLSServerName overrides the name the receiver's certificate is
	// checked against (default: Host).
	TLSServerName string  `json:"tlsServerName,omitempty"`
	Format        string  `json:"format"`      // "" = preset default
	Rate          float64 `json:"rate"`        // events per second, fractional ok
	RateMode      string  `json:"rateMode"`    // steady | jitter | burst
	JitterPct     float64 `json:"jitterPct"`   // jitter mode: ± percent (default 30)
	BurstFactor   float64 `json:"burstFactor"` // burst mode: rate multiplier (default 5)
	BurstEvery    int     `json:"burstEvery"`  // burst mode: seconds between bursts (default 30)
	BurstLen      int     `json:"burstLen"`    // burst mode: burst length seconds (default 5)
	DurationSec   int     `json:"durationSec"` // 0 = run until stopped
	MaxEvents     int64   `json:"maxEvents"`   // 0 = unlimited
	Hostname      string  `json:"hostname"`    // override preset hostname
	Appname       string  `json:"appname"`
	Facility      int     `json:"facility"` // -1 = preset default
	Autostart     bool    `json:"autostart"`
}

// maxRate is the ceiling for both the configured rate and the effective
// rate after jitter/burst multipliers.
const maxRate = 50000

// Validate checks the parts that would otherwise fail at start time.
func (c *JobConfig) Validate() error {
	if c.Name == "" {
		return fmt.Errorf("job needs a name")
	}
	if c.Host == "" {
		return fmt.Errorf("job needs a destination host")
	}
	if c.Port < 1 || c.Port > 65535 {
		return fmt.Errorf("port must be 1-65535")
	}
	switch c.Transport {
	case "udp", "tcp", "tls":
	default:
		return fmt.Errorf("transport must be udp, tcp or tls")
	}
	// The TLS fields are checked even for udp/tcp, where they are kept but
	// unused, so switching the transport back never surfaces a bad value.
	c.TLSCA = strings.TrimSpace(c.TLSCA)
	c.TLSServerName = strings.TrimSpace(c.TLSServerName)
	if c.TLSCA != "" {
		if c.Transport == "tls" && c.TLSInsecure {
			return fmt.Errorf("a trusted CA/certificate and skipping verification exclude each other: clear one")
		}
		if _, err := ParseTrustedCerts(c.TLSCA); err != nil {
			return err
		}
	}
	if err := checkServerName(c.TLSServerName); err != nil {
		return err
	}
	if c.Rate <= 0 {
		return fmt.Errorf("rate must be > 0 events/sec")
	}
	if c.Rate > maxRate {
		return fmt.Errorf("rate capped at %d events/sec", maxRate)
	}
	switch c.RateMode {
	case "", "steady", "jitter", "burst":
	default:
		return fmt.Errorf("rateMode must be steady, jitter or burst")
	}
	return nil
}

// JobStatus is the live view of a job exposed to the UI.
type JobStatus struct {
	JobConfig
	Running   bool      `json:"running"`
	Sent      int64     `json:"sent"`
	Errors    int64     `json:"errors"`
	LastError string    `json:"lastError,omitempty"`
	StartedAt time.Time `json:"startedAt,omitempty"`
	ActualEPS float64   `json:"actualEps"`
}

// jobState is the lifecycle of a job's generator goroutine:
//
//	idle --start--> running --halt--> stopping --run exits--> idle
//	                running --run exits on its own (duration/maxEvents)--> idle
//
// All transitions happen under job.mu and only finish (run exit, or a
// failed start) moves a job back to idle, so a second stop can never
// double-close anything and a start can never overlap a run that is still
// winding down.
type jobState int

const (
	stateIdle jobState = iota
	stateRunning
	stateStopping
)

// stopTimeout bounds how long Stop/Delete wait for a run loop to exit. The
// loop checks for cancellation between messages and the senders abort
// in-flight dials/writes on cancel, so this is a safety net, not a pace.
var stopTimeout = 10 * time.Second

var errJobNotFound = errors.New("job not found")

// job is the runtime state behind a JobConfig.
type job struct {
	mu        sync.Mutex
	cfg       JobConfig // guarded by mu; a run works on its own copy
	state     jobState
	deleted   bool               // set by Manager.Delete: never start again
	cancel    context.CancelFunc // non-nil while running/stopping
	done      chan struct{}      // closed once the current run has exited
	startedAt time.Time

	sent      atomic.Int64
	errors    atomic.Int64
	lastError atomic.Value // string

	// sliding window for actual-EPS display
	winStart atomic.Int64 // unix nano
	winSent  atomic.Int64
	epsMilli atomic.Int64 // rate of the last completed window, in events/1000s
}

// onEvent receives every successfully sent message (for the live tail).
type onEvent func(jobID, jobName, msg string)

// presetLookup resolves a preset by name.
type presetLookup func(name string) (*preset.Preset, bool)

// config returns a copy of the job's config.
func (j *job) config() JobConfig {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.cfg
}

// setConfig replaces the config; the job must be idle.
func (j *job) setConfig(cfg JobConfig) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.state != stateIdle {
		return fmt.Errorf("stop the job before editing it")
	}
	j.cfg = cfg
	return nil
}

// markDeleted prevents any future start. A start that already got past
// the check is stopped by the halt that follows in Manager.Delete.
func (j *job) markDeleted() {
	j.mu.Lock()
	j.deleted = true
	j.mu.Unlock()
}

func (j *job) start(lookup presetLookup, emit onEvent) error {
	j.mu.Lock()
	if j.deleted {
		j.mu.Unlock()
		return errJobNotFound
	}
	switch j.state {
	case stateRunning:
		j.mu.Unlock()
		return fmt.Errorf("job already running")
	case stateStopping:
		j.mu.Unlock()
		return fmt.Errorf("job is still stopping, try again")
	}
	cfg := j.cfg
	p, ok := lookup(cfg.Preset)
	if !ok {
		j.mu.Unlock()
		return fmt.Errorf("preset %q not found", cfg.Preset)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	j.state = stateRunning
	j.cancel = cancel
	j.done = done
	j.startedAt = time.Now()
	startedAt := j.startedAt
	j.sent.Store(0)
	j.errors.Store(0)
	j.lastError.Store("")
	j.winStart.Store(startedAt.UnixNano())
	j.winSent.Store(0)
	j.epsMilli.Store(0)
	j.mu.Unlock()

	// Dial outside the lock (DNS can be slow). A concurrent halt cancels ctx
	// and waits on done, which finish closes on every path.
	sender, err := newJobSender(ctx, cfg)
	if err != nil {
		j.finish(done)
		return err
	}
	r := p.NewRenderer(preset.RenderOpts{
		Hostname: cfg.Hostname,
		Appname:  cfg.Appname,
		Facility: cfg.Facility,
		Format:   cfg.Format,
	})
	activeRuns.Add(1)
	go j.run(ctx, cfg, startedAt, sender, r, emit, done)
	return nil
}

// newJobSender builds the sender for a job's destination and transport.
func newJobSender(ctx context.Context, cfg JobConfig) (Sender, error) {
	var tlsConf *tls.Config
	if cfg.Transport == "tls" {
		var err error
		if tlsConf, err = TLSConfig(cfg.TLSInsecure, cfg.TLSCA, cfg.TLSServerName); err != nil {
			return nil, err
		}
	}
	return NewSender(ctx, cfg.Transport, cfg.Host, cfg.Port, tlsConf)
}

// finish moves the job back to idle and releases waiters. It runs exactly
// once per successful state change to running: from the run goroutine, or
// from start itself when setup fails.
func (j *job) finish(done chan struct{}) {
	j.mu.Lock()
	if j.cancel != nil {
		j.cancel()
		j.cancel = nil
	}
	j.state = stateIdle
	j.mu.Unlock()
	close(done)
}

// halt cancels the current run (if any) and waits up to timeout for it to
// exit. Safe to call any number of times, concurrently.
func (j *job) halt(timeout time.Duration) error {
	j.mu.Lock()
	if j.state == stateIdle {
		j.mu.Unlock()
		return nil
	}
	j.cancel()
	j.state = stateStopping
	done := j.done
	j.mu.Unlock()

	t := time.NewTimer(timeout)
	defer t.Stop()
	select {
	case <-done:
		return nil
	case <-t.C:
		return fmt.Errorf("job did not stop within %s", timeout)
	}
}

// activeRuns counts live run goroutines (tests use it to prove that no
// generator outlives its job).
var activeRuns atomic.Int64

func (j *job) run(ctx context.Context, cfg JobConfig, startedAt time.Time, sender Sender, r *preset.Renderer, emit onEvent, done chan struct{}) {
	defer j.finish(done)
	defer activeRuns.Add(-1)
	defer sender.Close()

	ticker := time.NewTicker(tick)
	defer ticker.Stop()

	rs := newRateShape(cfg, rand.New(rand.NewSource(time.Now().UnixNano())))
	pace := newPacer(startedAt) // first event goes out on the first tick
	deadline := time.Time{}
	if cfg.DurationSec > 0 {
		deadline = startedAt.Add(time.Duration(cfg.DurationSec) * time.Second)
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		now := time.Now()
		if !deadline.IsZero() && now.After(deadline) {
			return
		}
		n := pace.take(now, rs.rate(now.Sub(startedAt)))

		for i := 0; i < n; i++ {
			if ctx.Err() != nil {
				return
			}
			msg, err := r.Render()
			if err != nil {
				j.errors.Add(1)
				j.lastError.Store(err.Error())
				continue
			}
			if err := sender.Send(msg); err != nil {
				if ctx.Err() != nil {
					return // aborted by a stop, not a delivery failure
				}
				j.errors.Add(1)
				j.lastError.Store(err.Error())
			} else {
				j.sent.Add(1)
				j.winSent.Add(1)
				emit(cfg.ID, cfg.Name, msg)
			}
			if cfg.MaxEvents > 0 && j.sent.Load() >= cfg.MaxEvents {
				return
			}
		}
		j.rollWindow()
	}
}

// tick is the run loop's wake-up interval.
const tick = 50 * time.Millisecond

// pacer is a token bucket refilled from the time that actually elapsed
// since the previous wake-up, so late or missed ticks don't lose events.
// It holds at most two ticks' worth (and at least one event): a missed
// tick is made up, but a stalled or slow sender never builds a backlog
// that would later come out as an over-rate burst.
type pacer struct {
	last   time.Time
	tokens float64
}

func newPacer(start time.Time) *pacer {
	return &pacer{last: start, tokens: 1}
}

// take refills the bucket for the time elapsed up to now at rate events/s
// and returns how many whole events to emit.
func (p *pacer) take(now time.Time, rate float64) int {
	if dt := now.Sub(p.last); dt > 0 {
		p.tokens += rate * dt.Seconds()
	}
	p.last = now
	// +1 keeps the fractional carry of low rates (0.5 EPS must not lose
	// the overshoot past a whole event)
	if capacity := 1 + rate*2*tick.Seconds(); p.tokens > capacity {
		p.tokens = capacity
	}
	n := int(p.tokens)
	p.tokens -= float64(n)
	return n
}

// rateShape turns a config's base rate and mode into the target rate at a
// given point of the run.
type rateShape struct {
	base, jitterPct, burstFactor float64
	mode                         string
	burstEvery, burstLen         time.Duration
	rng                          *rand.Rand
}

func newRateShape(cfg JobConfig, rng *rand.Rand) rateShape {
	rs := rateShape{
		base:        cfg.Rate,
		mode:        cfg.RateMode,
		jitterPct:   cfg.JitterPct,
		burstFactor: cfg.BurstFactor,
		burstEvery:  time.Duration(max(cfg.BurstEvery, 10)) * time.Second,
		burstLen:    time.Duration(max(cfg.BurstLen, 1)) * time.Second,
		rng:         rng,
	}
	if rs.jitterPct <= 0 {
		rs.jitterPct = 30
	}
	if rs.burstFactor <= 1 {
		rs.burstFactor = 5
	}
	return rs
}

// rate returns the target events/s at elapsed time into the run, never
// above maxRate (so a 20k EPS job with a 5x burst bursts at 50k, not 100k).
func (rs rateShape) rate(elapsed time.Duration) float64 {
	rate := rs.base
	switch rs.mode {
	case "jitter":
		rate *= 1 + (rs.rng.Float64()*2-1)*rs.jitterPct/100
	case "burst":
		if elapsed%rs.burstEvery < rs.burstLen {
			rate *= rs.burstFactor
		}
	}
	return min(max(rate, 0), maxRate)
}

// rollWindow rolls the EPS window every ~5s, keeping the completed window's rate.
func (j *job) rollWindow() {
	if ws := j.winStart.Load(); time.Since(time.Unix(0, ws)) > 5*time.Second {
		elapsed := time.Since(time.Unix(0, ws)).Seconds()
		j.epsMilli.Store(int64(float64(j.winSent.Load()) / elapsed * 1000))
		j.winStart.Store(time.Now().UnixNano())
		j.winSent.Store(0)
	}
}

func (j *job) status() JobStatus {
	j.mu.Lock()
	cfg := j.cfg
	running := j.state == stateRunning
	started := j.startedAt
	j.mu.Unlock()
	st := JobStatus{
		JobConfig: cfg,
		Running:   running,
		Sent:      j.sent.Load(),
		Errors:    j.errors.Load(),
	}
	if le, _ := j.lastError.Load().(string); le != "" {
		st.LastError = le
	}
	if running {
		st.StartedAt = started
		elapsed := time.Since(time.Unix(0, j.winStart.Load())).Seconds()
		if elapsed >= 1 {
			st.ActualEPS = float64(j.winSent.Load()) / elapsed
		} else {
			st.ActualEPS = float64(j.epsMilli.Load()) / 1000
		}
	}
	return st
}
