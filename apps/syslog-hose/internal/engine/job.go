package engine

import (
	"fmt"
	"math/rand"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tesla/syshose/internal/preset"
)

// JobConfig is the persisted definition of a generator stream.
type JobConfig struct {
	ID          string  `json:"id"`
	Name        string  `json:"name"`
	Preset      string  `json:"preset"`
	Host        string  `json:"host"`
	Port        int     `json:"port"`
	Transport   string  `json:"transport"`   // udp | tcp | tls
	TLSInsecure bool    `json:"tlsInsecure"` // skip cert verification (labs)
	Format      string  `json:"format"`      // "" = preset default
	Rate        float64 `json:"rate"`        // events per second, fractional ok
	RateMode    string  `json:"rateMode"`    // steady | jitter | burst
	JitterPct   float64 `json:"jitterPct"`   // jitter mode: ± percent (default 30)
	BurstFactor float64 `json:"burstFactor"` // burst mode: rate multiplier (default 5)
	BurstEvery  int     `json:"burstEvery"`  // burst mode: seconds between bursts (default 30)
	BurstLen    int     `json:"burstLen"`    // burst mode: burst length seconds (default 5)
	DurationSec int     `json:"durationSec"` // 0 = run until stopped
	MaxEvents   int64   `json:"maxEvents"`   // 0 = unlimited
	Hostname    string  `json:"hostname"`    // override preset hostname
	Appname     string  `json:"appname"`
	Facility    int     `json:"facility"` // -1 = preset default
	Autostart   bool    `json:"autostart"`
}

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
	if c.Rate <= 0 {
		return fmt.Errorf("rate must be > 0 events/sec")
	}
	if c.Rate > 50000 {
		return fmt.Errorf("rate capped at 50000 events/sec")
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

// job is the runtime state behind a JobConfig.
type job struct {
	cfg     JobConfig
	mu      sync.Mutex
	running bool
	stop    chan struct{}
	done    chan struct{}

	sent      atomic.Int64
	errors    atomic.Int64
	lastError atomic.Value // string
	startedAt time.Time

	// sliding window for actual-EPS display
	winStart atomic.Int64 // unix nano
	winSent  atomic.Int64
	epsMilli atomic.Int64 // rate of the last completed window, in events/1000s
}

// onEvent receives every successfully sent message (for the live tail).
type onEvent func(jobID, jobName, msg string)

// onExit is called when the run loop ends on its own (duration/maxEvents).
type onExit func(jobID string)

func (j *job) start(p *preset.Preset, emit onEvent, exited onExit) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.running {
		return fmt.Errorf("job already running")
	}
	sender, err := NewSender(j.cfg.Transport, j.cfg.Host, j.cfg.Port, j.cfg.TLSInsecure)
	if err != nil {
		return err
	}
	r := p.NewRenderer(preset.RenderOpts{
		Hostname: j.cfg.Hostname,
		Appname:  j.cfg.Appname,
		Facility: j.cfg.Facility,
		Format:   j.cfg.Format,
	})
	j.running = true
	j.stop = make(chan struct{})
	j.done = make(chan struct{})
	j.startedAt = time.Now()
	j.sent.Store(0)
	j.errors.Store(0)
	j.lastError.Store("")
	go j.run(sender, r, emit, exited)
	return nil
}

func (j *job) run(sender Sender, r *preset.Renderer, emit onEvent, exited onExit) {
	defer close(j.done)
	defer sender.Close()

	const tick = 50 * time.Millisecond
	ticker := time.NewTicker(tick)
	defer ticker.Stop()

	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	tokens := 1.0 // emit the first event immediately
	deadline := time.Time{}
	if j.cfg.DurationSec > 0 {
		deadline = time.Now().Add(time.Duration(j.cfg.DurationSec) * time.Second)
	}
	jitter := j.cfg.JitterPct
	if jitter <= 0 {
		jitter = 30
	}
	burstFactor := j.cfg.BurstFactor
	if burstFactor <= 1 {
		burstFactor = 5
	}
	burstEvery := time.Duration(max(j.cfg.BurstEvery, 10)) * time.Second
	burstLen := time.Duration(max(j.cfg.BurstLen, 1)) * time.Second

	j.winStart.Store(time.Now().UnixNano())
	j.winSent.Store(0)
	stopped := false

	for !stopped {
		select {
		case <-j.stop:
			stopped = true
			continue
		case <-ticker.C:
		}
		if !deadline.IsZero() && time.Now().After(deadline) {
			break
		}

		rate := j.cfg.Rate
		switch j.cfg.RateMode {
		case "jitter":
			f := 1 + (rng.Float64()*2-1)*jitter/100
			rate *= f
		case "burst":
			if time.Since(j.startedAt)%burstEvery < burstLen {
				rate *= burstFactor
			}
		}
		tokens += rate * tick.Seconds()
		n := int(tokens)
		if n > 2500 { // cap per-tick batch so a stop stays responsive
			n = 2500
		}
		tokens -= float64(n)

		for i := 0; i < n; i++ {
			msg, err := r.Render()
			if err != nil {
				j.errors.Add(1)
				j.lastError.Store(err.Error())
				continue
			}
			if err := sender.Send(msg); err != nil {
				j.errors.Add(1)
				j.lastError.Store(err.Error())
			} else {
				j.sent.Add(1)
				j.winSent.Add(1)
				emit(j.cfg.ID, j.cfg.Name, msg)
			}
			if j.cfg.MaxEvents > 0 && j.sent.Load() >= j.cfg.MaxEvents {
				stopped = true
				break
			}
		}
		// roll the EPS window every ~5s, keeping the completed window's rate
		if ws := j.winStart.Load(); time.Since(time.Unix(0, ws)) > 5*time.Second {
			elapsed := time.Since(time.Unix(0, ws)).Seconds()
			j.epsMilli.Store(int64(float64(j.winSent.Load()) / elapsed * 1000))
			j.winStart.Store(time.Now().UnixNano())
			j.winSent.Store(0)
		}
	}

	j.mu.Lock()
	j.running = false
	j.mu.Unlock()
	exited(j.cfg.ID)
}

func (j *job) halt() {
	j.mu.Lock()
	if !j.running {
		j.mu.Unlock()
		return
	}
	close(j.stop)
	done := j.done
	j.mu.Unlock()
	<-done
}

func (j *job) status() JobStatus {
	j.mu.Lock()
	running := j.running
	started := j.startedAt
	j.mu.Unlock()
	st := JobStatus{
		JobConfig: j.cfg,
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

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
