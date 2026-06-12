// Package supervisor owns the syslog-ng child process: it starts it,
// restarts it if it dies, validates candidate configs with --syntax-only,
// swaps configs atomically and reloads via SIGHUP, keeping a bounded
// history of applied versions for rollback.
package supervisor

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const historyKeep = 20

type Status struct {
	Running   bool      `json:"running"`
	PID       int       `json:"pid"`
	Restarts  int       `json:"restarts"`
	Version   string    `json:"version"`
	LastApply time.Time `json:"lastApply"`
	LastError string    `json:"lastError"`
	Log       []string  `json:"log"`
}

type HistoryEntry struct {
	ID   string    `json:"id"`
	Time time.Time `json:"time"`
}

type Supervisor struct {
	bin     string
	dataDir string // e.g. /data/syslog-ng

	mu        sync.Mutex
	cmd       *exec.Cmd
	running   bool
	restarts  int
	version   string
	lastApply time.Time
	lastErr   string
	logRing   []string
	stop      context.CancelFunc
	done      chan struct{}
}

func New(bin, dataDir string) *Supervisor {
	return &Supervisor{bin: bin, dataDir: dataDir}
}

func (s *Supervisor) ConfPath() string   { return filepath.Join(s.dataDir, "current.conf") }
func (s *Supervisor) historyDir() string { return filepath.Join(s.dataDir, "history") }
func (s *Supervisor) graphFor(id string) string {
	return filepath.Join(s.historyDir(), id+".graph.json")
}
func (s *Supervisor) confFor(id string) string {
	return filepath.Join(s.historyDir(), id+".conf")
}

// Version asks the binary once and caches the "x.y" config version.
func (s *Supervisor) Version() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.version != "" {
		return s.version
	}
	out, err := exec.Command(s.bin, "--version").CombinedOutput()
	if err == nil {
		// first line looks like: "syslog-ng 4 (4.8.1)"
		if m := regexp.MustCompile(`(\d+\.\d+)`).FindString(string(out)); m != "" {
			s.version = m
			return m
		}
	}
	s.version = "4.8"
	return s.version
}

// Start writes initialConf if no config exists yet, then runs syslog-ng in
// the foreground, restarting it with backoff until ctx is cancelled.
func (s *Supervisor) Start(ctx context.Context, initialConf string) error {
	if err := os.MkdirAll(s.historyDir(), 0o755); err != nil {
		return err
	}
	if _, err := os.Stat(s.ConfPath()); os.IsNotExist(err) {
		if err := atomicWrite(s.ConfPath(), []byte(initialConf)); err != nil {
			return err
		}
	}
	ctx, cancel := context.WithCancel(ctx)
	s.stop = cancel
	s.done = make(chan struct{})
	go s.runLoop(ctx)
	return nil
}

func (s *Supervisor) runLoop(ctx context.Context) {
	defer close(s.done)
	backoff := time.Second
	for {
		start := time.Now()
		err := s.runOnce(ctx)
		s.mu.Lock()
		s.running = false
		s.cmd = nil
		if err != nil && ctx.Err() == nil {
			s.lastErr = fmt.Sprintf("syslog-ng exited: %v", err)
			s.restarts++
		}
		s.mu.Unlock()
		if ctx.Err() != nil {
			return
		}
		if time.Since(start) > time.Minute {
			backoff = time.Second
		}
		select {
		case <-time.After(backoff):
		case <-ctx.Done():
			return
		}
		if backoff < 30*time.Second {
			backoff *= 2
		}
	}
}

func (s *Supervisor) runOnce(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, s.bin,
		"-F", "-e", "--no-caps",
		"-f", s.ConfPath(),
		"--persist-file", filepath.Join(s.dataDir, "persist"),
		"--pidfile", filepath.Join(s.dataDir, "syslog-ng.pid"),
	)
	cmd.Cancel = func() error { return cmd.Process.Signal(syscall.SIGTERM) }
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return err
	}
	cmd.Stdout = cmd.Stderr
	if err := cmd.Start(); err != nil {
		return err
	}
	s.mu.Lock()
	s.cmd = cmd
	s.running = true
	s.mu.Unlock()
	go s.consume(stderr)
	return cmd.Wait()
}

func (s *Supervisor) consume(r io.Reader) {
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := sc.Text()
		fmt.Fprintf(os.Stderr, "syslog-ng: %s\n", line)
		s.mu.Lock()
		s.logRing = append(s.logRing, line)
		if len(s.logRing) > 50 {
			s.logRing = s.logRing[len(s.logRing)-50:]
		}
		s.mu.Unlock()
	}
}

// Shutdown stops the child and waits for the run loop to exit.
func (s *Supervisor) Shutdown() {
	if s.stop != nil {
		s.stop()
		<-s.done
	}
}

// Validate runs `syslog-ng --syntax-only` against conf and returns its
// stderr as the error message on failure.
func (s *Supervisor) Validate(conf string) error {
	tmp, err := os.CreateTemp(s.dataDir, "candidate-*.conf")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.WriteString(conf); err != nil {
		tmp.Close()
		return err
	}
	tmp.Close()
	out, err := exec.Command(s.bin, "--syntax-only", "-f", tmp.Name()).CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg == "" {
			msg = err.Error()
		}
		return fmt.Errorf("%s", msg)
	}
	return nil
}

// Apply validates conf, archives the previous config+graph pair, swaps in
// the new config atomically and signals syslog-ng to reload.
func (s *Supervisor) Apply(conf string, graphJSON []byte) error {
	if err := s.Validate(conf); err != nil {
		s.mu.Lock()
		s.lastErr = err.Error()
		s.mu.Unlock()
		return err
	}
	id := time.Now().UTC().Format("20060102-150405.000")
	if err := atomicWrite(s.confFor(id), []byte(conf)); err != nil {
		return err
	}
	if err := atomicWrite(s.graphFor(id), graphJSON); err != nil {
		return err
	}
	if err := atomicWrite(s.ConfPath(), []byte(conf)); err != nil {
		return err
	}
	s.prune()
	s.mu.Lock()
	s.lastApply = time.Now()
	s.lastErr = ""
	s.mu.Unlock()
	return s.Reload()
}

// Rollback re-applies a config from history and returns its graph JSON so
// the caller can restore the matching graph state.
func (s *Supervisor) Rollback(id string) ([]byte, error) {
	conf, err := os.ReadFile(s.confFor(id))
	if err != nil {
		return nil, fmt.Errorf("history entry %s: %w", id, err)
	}
	graphJSON, err := os.ReadFile(s.graphFor(id))
	if err != nil {
		return nil, fmt.Errorf("history entry %s: %w", id, err)
	}
	if err := s.Validate(string(conf)); err != nil {
		return nil, err
	}
	if err := atomicWrite(s.ConfPath(), conf); err != nil {
		return nil, err
	}
	s.mu.Lock()
	s.lastApply = time.Now()
	s.lastErr = ""
	s.mu.Unlock()
	return graphJSON, s.Reload()
}

// HistoryConfig returns the archived config text for one history entry.
func (s *Supervisor) HistoryConfig(id string) ([]byte, error) {
	data, err := os.ReadFile(s.confFor(id))
	if err != nil {
		return nil, fmt.Errorf("history entry %s: %w", id, err)
	}
	return data, nil
}

func (s *Supervisor) History() []HistoryEntry {
	entries, _ := os.ReadDir(s.historyDir())
	// Non-nil so the API answers [] (not null) on a fresh install — the UI
	// maps over it.
	out := []HistoryEntry{}
	for _, e := range entries {
		if id, ok := strings.CutSuffix(e.Name(), ".conf"); ok {
			t, err := time.Parse("20060102-150405.000", id)
			if err != nil {
				continue
			}
			out = append(out, HistoryEntry{ID: id, Time: t})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID > out[j].ID })
	return out
}

func (s *Supervisor) prune() {
	h := s.History()
	for i := historyKeep; i < len(h); i++ {
		os.Remove(s.confFor(h[i].ID))
		os.Remove(s.graphFor(h[i].ID))
	}
}

// Reload sends SIGHUP; syslog-ng re-reads its config without dropping
// established TCP connections.
func (s *Supervisor) Reload() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cmd == nil || s.cmd.Process == nil {
		return fmt.Errorf("syslog-ng is not running")
	}
	return s.cmd.Process.Signal(syscall.SIGHUP)
}

// ctlBin returns the syslog-ng-ctl path next to the syslog-ng binary, so a
// custom VALVE_SYSLOG_NG path still finds its control client.
func (s *Supervisor) ctlBin() string {
	dir, file := filepath.Split(s.bin)
	if strings.Contains(file, "syslog-ng") {
		return filepath.Join(dir, strings.Replace(file, "syslog-ng", "syslog-ng-ctl", 1))
	}
	return "syslog-ng-ctl"
}

// Stats asks the running syslog-ng (over its default control socket) for the
// cumulative per-statement "processed" message counters, keyed by the
// statement name codegen assigned (s_<ident> for sources, d_<ident> for
// destinations). The caller maps those back to graph nodes. Returns an error
// if syslog-ng isn't answering; counters are monotonic until a reload/restart.
func (s *Supervisor) Stats() (map[string]int64, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, s.ctlBin(), "stats").Output()
	if err != nil {
		return nil, fmt.Errorf("syslog-ng-ctl stats: %w", err)
	}
	res := map[string]int64{}
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		// SourceName;SourceId;SourceInstance;State;Type;Number
		f := strings.Split(sc.Text(), ";")
		if len(f) < 6 || f[4] != "processed" {
			continue
		}
		// Statement-level rows carry the plain statement name in SourceId;
		// driver-level rows (dst.network, …) use name#instance — skip those.
		if f[0] != "source" && f[0] != "destination" {
			continue
		}
		if n, err := strconv.ParseInt(f[5], 10, 64); err == nil {
			res[f[1]] = n
		}
	}
	return res, sc.Err()
}

func (s *Supervisor) Status() Status {
	v := s.Version()
	s.mu.Lock()
	defer s.mu.Unlock()
	st := Status{
		Running:   s.running,
		Restarts:  s.restarts,
		Version:   v,
		LastApply: s.lastApply,
		LastError: s.lastErr,
		Log:       append([]string(nil), s.logRing...),
	}
	if s.cmd != nil && s.cmd.Process != nil {
		st.PID = s.cmd.Process.Pid
	}
	return st
}

func atomicWrite(path string, data []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
