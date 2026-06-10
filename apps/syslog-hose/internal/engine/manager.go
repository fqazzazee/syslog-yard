package engine

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/syslog-yard/syslog-hose/internal/preset"
)

// TailEvent is one emitted message kept for the live tail.
type TailEvent struct {
	Seq     int64     `json:"seq"`
	JobID   string    `json:"jobId"`
	JobName string    `json:"jobName"`
	Time    time.Time `json:"time"`
	Message string    `json:"message"`
}

const tailSize = 200

// Manager owns all jobs, their persistence and the shared tail buffer.
type Manager struct {
	mu      sync.RWMutex
	jobs    map[string]*job
	store   *preset.Store
	dataDir string

	tailMu  sync.Mutex
	tail    [tailSize]TailEvent
	tailLen int
	tailSeq int64
}

// NewManager loads persisted jobs from dataDir/jobs.json and autostarts
// the ones marked for it.
func NewManager(store *preset.Store, dataDir string) (*Manager, error) {
	m := &Manager{jobs: map[string]*job{}, store: store, dataDir: dataDir}
	path := m.jobsPath()
	if raw, err := os.ReadFile(path); err == nil {
		var cfgs []JobConfig
		if err := json.Unmarshal(raw, &cfgs); err != nil {
			return nil, fmt.Errorf("corrupt %s: %w", path, err)
		}
		for _, c := range cfgs {
			m.jobs[c.ID] = &job{cfg: c}
		}
	}
	for _, j := range m.jobs {
		if j.cfg.Autostart {
			if err := m.Start(j.cfg.ID); err != nil {
				fmt.Fprintf(os.Stderr, "syslog-hose: autostart %q: %v\n", j.cfg.Name, err)
			}
		}
	}
	return m, nil
}

func (m *Manager) jobsPath() string { return filepath.Join(m.dataDir, "jobs.json") }

func (m *Manager) persist() {
	m.mu.RLock()
	cfgs := make([]JobConfig, 0, len(m.jobs))
	for _, j := range m.jobs {
		cfgs = append(cfgs, j.cfg)
	}
	m.mu.RUnlock()
	sort.Slice(cfgs, func(i, k int) bool { return cfgs[i].Name < cfgs[k].Name })
	raw, _ := json.MarshalIndent(cfgs, "", "  ")
	tmp := m.jobsPath() + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o644); err == nil {
		os.Rename(tmp, m.jobsPath())
	}
}

// Create validates, stores and persists a new job config.
func (m *Manager) Create(cfg JobConfig) (JobStatus, error) {
	if err := cfg.Validate(); err != nil {
		return JobStatus{}, err
	}
	if _, ok := m.store.Get(cfg.Preset); !ok {
		return JobStatus{}, fmt.Errorf("preset %q not found", cfg.Preset)
	}
	b := make([]byte, 6)
	rand.Read(b)
	cfg.ID = hex.EncodeToString(b)
	j := &job{cfg: cfg}
	m.mu.Lock()
	m.jobs[cfg.ID] = j
	m.mu.Unlock()
	m.persist()
	return j.status(), nil
}

// Update replaces a job's config (job must be stopped).
func (m *Manager) Update(id string, cfg JobConfig) (JobStatus, error) {
	if err := cfg.Validate(); err != nil {
		return JobStatus{}, err
	}
	if _, ok := m.store.Get(cfg.Preset); !ok {
		return JobStatus{}, fmt.Errorf("preset %q not found", cfg.Preset)
	}
	m.mu.Lock()
	j, ok := m.jobs[id]
	if !ok {
		m.mu.Unlock()
		return JobStatus{}, fmt.Errorf("job not found")
	}
	j.mu.Lock()
	running := j.running
	j.mu.Unlock()
	if running {
		m.mu.Unlock()
		return JobStatus{}, fmt.Errorf("stop the job before editing it")
	}
	cfg.ID = id
	j.cfg = cfg
	m.mu.Unlock()
	m.persist()
	return j.status(), nil
}

// Delete stops (if needed) and removes a job.
func (m *Manager) Delete(id string) error {
	m.mu.Lock()
	j, ok := m.jobs[id]
	if !ok {
		m.mu.Unlock()
		return fmt.Errorf("job not found")
	}
	delete(m.jobs, id)
	m.mu.Unlock()
	j.halt()
	m.persist()
	return nil
}

// Start launches a job's generator goroutine.
func (m *Manager) Start(id string) error {
	m.mu.RLock()
	j, ok := m.jobs[id]
	m.mu.RUnlock()
	if !ok {
		return fmt.Errorf("job not found")
	}
	p, ok := m.store.Get(j.cfg.Preset)
	if !ok {
		return fmt.Errorf("preset %q not found", j.cfg.Preset)
	}
	return j.start(p, m.recordEvent, func(string) {})
}

// Stop halts a running job and waits for its goroutine to exit.
func (m *Manager) Stop(id string) error {
	m.mu.RLock()
	j, ok := m.jobs[id]
	m.mu.RUnlock()
	if !ok {
		return fmt.Errorf("job not found")
	}
	j.halt()
	return nil
}

// StopAll halts every running job (used on shutdown and by the UI).
func (m *Manager) StopAll() {
	m.mu.RLock()
	jobs := make([]*job, 0, len(m.jobs))
	for _, j := range m.jobs {
		jobs = append(jobs, j)
	}
	m.mu.RUnlock()
	for _, j := range jobs {
		j.halt()
	}
}

// List returns the live status of every job, sorted by name.
func (m *Manager) List() []JobStatus {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]JobStatus, 0, len(m.jobs))
	for _, j := range m.jobs {
		out = append(out, j.status())
	}
	sort.Slice(out, func(i, k int) bool { return out[i].Name < out[k].Name })
	return out
}

// recordEvent pushes a sent message into the shared tail ring buffer.
func (m *Manager) recordEvent(jobID, jobName, msg string) {
	m.tailMu.Lock()
	m.tailSeq++
	m.tail[int(m.tailSeq)%tailSize] = TailEvent{
		Seq: m.tailSeq, JobID: jobID, JobName: jobName, Time: time.Now(), Message: msg,
	}
	if m.tailLen < tailSize {
		m.tailLen++
	}
	m.tailMu.Unlock()
}

// TailSince returns buffered events with Seq > since (capped at the ring size).
func (m *Manager) TailSince(since int64) []TailEvent {
	m.tailMu.Lock()
	defer m.tailMu.Unlock()
	out := []TailEvent{}
	lo := m.tailSeq - int64(m.tailLen) + 1
	if since+1 > lo {
		lo = since + 1
	}
	for s := lo; s <= m.tailSeq; s++ {
		out = append(out, m.tail[int(s)%tailSize])
	}
	return out
}
