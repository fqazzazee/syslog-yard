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

	persistMu sync.Mutex // serializes snapshot+write of jobs.json

	tailMu  sync.Mutex
	tail    [tailSize]TailEvent
	tailLen int
	tailSeq int64
}

// NewManager loads persisted jobs from dataDir/jobs.json and autostarts
// the ones marked for it.
func NewManager(store *preset.Store, dataDir string) (*Manager, error) {
	m := &Manager{
		jobs: map[string]*job{}, store: store, dataDir: dataDir,
		// Seed tail sequence numbers from the clock so they keep increasing
		// across restarts: the UI keys tail lines by seq and keeps lines
		// from before a reconnect. Microseconds stay below 2^53 (exact in
		// a JS number), and ids can only collide if the hose averaged more
		// than 1M events/s for its whole previous lifetime.
		tailSeq: time.Now().UnixMicro(),
	}
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

// persist writes the current job set to jobs.json. persistMu spans the
// snapshot and the write, so concurrent mutations land on disk in order
// (an older snapshot can never overwrite a newer one and resurrect a
// deleted job); the write is atomic and durable (unique temp file, fsync,
// rename, fsync of the directory). Errors are logged: the in-memory state
// stays authoritative until the next successful write.
func (m *Manager) persist() {
	m.persistMu.Lock()
	defer m.persistMu.Unlock()

	m.mu.RLock()
	cfgs := make([]JobConfig, 0, len(m.jobs))
	for _, j := range m.jobs {
		cfgs = append(cfgs, j.config())
	}
	m.mu.RUnlock()
	sort.Slice(cfgs, func(i, k int) bool { return cfgs[i].Name < cfgs[k].Name })
	raw, err := json.MarshalIndent(cfgs, "", "  ")
	if err == nil {
		err = writeFileAtomic(m.jobsPath(), raw, 0o644)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "syslog-hose: saving jobs: %v\n", err)
	}
}

func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	ok := false
	defer func() {
		if !ok {
			f.Close()
			os.Remove(tmp)
		}
	}()
	if _, err := f.Write(data); err != nil {
		return err
	}
	if err := f.Chmod(perm); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	ok = true
	if d, err := os.Open(dir); err == nil {
		err = d.Sync()
		d.Close()
		return err
	}
	return nil
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
	cfg.ID = id
	m.mu.Lock()
	j, ok := m.jobs[id]
	if !ok {
		m.mu.Unlock()
		return JobStatus{}, errJobNotFound
	}
	// the state check and the write happen under j.mu, so a concurrent
	// Start either sees the new config or makes this Update fail
	err := j.setConfig(cfg)
	m.mu.Unlock()
	if err != nil {
		return JobStatus{}, err
	}
	m.persist()
	return j.status(), nil
}

// Delete stops (if needed) and removes a job.
func (m *Manager) Delete(id string) error {
	m.mu.Lock()
	j, ok := m.jobs[id]
	if !ok {
		m.mu.Unlock()
		return errJobNotFound
	}
	delete(m.jobs, id)
	m.mu.Unlock()
	// mark first so a Start that already looked the job up can't revive
	// it after the halt below
	j.markDeleted()
	if err := j.halt(stopTimeout); err != nil {
		fmt.Fprintf(os.Stderr, "syslog-hose: delete %s: %v\n", id, err)
	}
	m.persist()
	return nil
}

func (m *Manager) get(id string) (*job, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	j, ok := m.jobs[id]
	return j, ok
}

// Start launches a job's generator goroutine.
func (m *Manager) Start(id string) error {
	j, ok := m.get(id)
	if !ok {
		return errJobNotFound
	}
	return j.start(m.store.Get, m.recordEvent)
}

// Stop halts a running job and waits for its goroutine to exit. Stopping
// an idle (or already stopping) job is a no-op, so double clicks and
// Stop + Stop-all races are harmless.
func (m *Manager) Stop(id string) error {
	j, ok := m.get(id)
	if !ok {
		return errJobNotFound
	}
	return j.halt(stopTimeout)
}

// StopAll halts every running job (used on shutdown and by the UI). Jobs
// are stopped in parallel so the total wait is bounded by one timeout.
func (m *Manager) StopAll() {
	m.mu.RLock()
	jobs := make([]*job, 0, len(m.jobs))
	for _, j := range m.jobs {
		jobs = append(jobs, j)
	}
	m.mu.RUnlock()
	var wg sync.WaitGroup
	for _, j := range jobs {
		wg.Go(func() {
			if err := j.halt(stopTimeout); err != nil {
				fmt.Fprintf(os.Stderr, "syslog-hose: stop all: %v\n", err)
			}
		})
	}
	wg.Wait()
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
	m.tail[m.tailSeq%tailSize] = TailEvent{
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
		out = append(out, m.tail[s%tailSize])
	}
	return out
}
