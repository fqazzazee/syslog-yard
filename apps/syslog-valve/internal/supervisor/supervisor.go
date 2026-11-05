// Package supervisor owns the syslog-ng child process: it starts it,
// restarts it if it dies, validates candidate configs with --syntax-only,
// swaps configs atomically and reloads via SIGHUP, keeping a bounded
// history of applied versions for rollback.
package supervisor

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
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
	reload    *reloadWait // set while a reload awaits confirmation
	stop      context.CancelFunc
	done      chan struct{}
	kick      chan struct{} // wakes the run loop out of its restart backoff

	// ReloadTimeout bounds how long Reload waits for syslog-ng to report
	// the outcome of a SIGHUP.
	ReloadTimeout time.Duration
	// StopTimeout is how long syslog-ng gets to exit after SIGTERM before
	// it is killed (and how long to keep reading its output after exit).
	StopTimeout time.Duration
}

// ErrNotRunning is returned (wrapped) by Apply when syslog-ng isn't
// running: the new config is installed and will be used when the run loop
// next starts it, but nothing confirmed it loads.
var ErrNotRunning = errors.New("syslog-ng is not running")

// ReloadError reports a config syslog-ng refused at reload time (after it
// passed --syntax-only), e.g. a port that is already bound. syslog-ng keeps
// running the previous config.
type ReloadError struct {
	Detail string
}

func (e *ReloadError) Error() string {
	if e.Detail == "" {
		return "syslog-ng could not load the new config and kept the previous one"
	}
	return "syslog-ng could not load the new config and kept the previous one: " + e.Detail
}

// reloadWait collects syslog-ng's log lines between a SIGHUP and its
// verdict.
type reloadWait struct {
	result chan error
	errs   []string
	failed bool
}

const (
	defaultReloadTimeout = 15 * time.Second
	defaultStopTimeout   = 10 * time.Second
)

func New(bin, dataDir string) *Supervisor {
	return &Supervisor{bin: bin, dataDir: dataDir, kick: make(chan struct{}, 1),
		ReloadTimeout: defaultReloadTimeout, StopTimeout: defaultStopTimeout}
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
		if w := s.reload; w != nil {
			s.reload = nil
			w.result <- fmt.Errorf("syslog-ng exited during reload: %v", err)
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
		case <-s.kick:
			backoff = time.Second
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
	// After SIGTERM, give syslog-ng StopTimeout to exit before it is
	// killed, and stop waiting on its output pipe that long after it exits
	// (a program() destination child could otherwise hold it open forever).
	cmd.WaitDelay = s.StopTimeout
	// A plain io.Writer (not StderrPipe) makes cmd.Wait wait for the copy
	// to drain, so syslog-ng's last lines before exiting aren't lost.
	lw := &lineWriter{emit: s.logLine}
	cmd.Stdout = lw
	cmd.Stderr = lw
	if err := cmd.Start(); err != nil {
		return err
	}
	s.mu.Lock()
	s.cmd = cmd
	s.running = true
	s.mu.Unlock()
	err := cmd.Wait()
	lw.flush()
	return err
}

// lineWriter splits the child's output into lines. exec runs Write from a
// single copying goroutine, so it needs no locking of its own.
type lineWriter struct {
	emit func(string)
	buf  []byte
}

const maxLine = 8192

func (w *lineWriter) Write(p []byte) (int, error) {
	w.buf = append(w.buf, p...)
	for {
		i := bytes.IndexByte(w.buf, '\n')
		if i < 0 {
			break
		}
		w.emit(string(w.buf[:i]))
		w.buf = w.buf[i+1:]
	}
	if len(w.buf) > maxLine {
		w.emit(string(w.buf))
		w.buf = nil
	}
	return len(p), nil
}

func (w *lineWriter) flush() {
	if len(w.buf) > 0 {
		w.emit(string(w.buf))
		w.buf = nil
	}
}

func (s *Supervisor) logLine(line string) {
	line = strings.TrimRight(line, "\r")
	fmt.Fprintf(os.Stderr, "syslog-ng: %s\n", line)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.logRing = append(s.logRing, line)
	if len(s.logRing) > 50 {
		s.logRing = s.logRing[len(s.logRing)-50:]
	}
	w := s.reload
	if w == nil {
		return
	}
	// syslog-ng's reload outcome messages (4.x):
	//   success: "Configuration reload finished;"
	//   init failure: "Error initializing new configuration, reverting to
	//     old config;" then "Configuration reload finished;"
	//   parse failure: "Error reloading configuration; reason=..."
	//   control-channel reload failure: "Configuration reload failed, ..."
	if strings.Contains(line, "Error") || strings.Contains(line, "error") {
		if len(w.errs) < 8 {
			w.errs = append(w.errs, stripTimestamp(line))
		}
	}
	switch {
	case strings.Contains(line, "reverting to old config"):
		w.failed = true
	case strings.Contains(line, "Error reloading configuration"),
		strings.Contains(line, "Configuration reload failed"):
		w.failed = true
		s.finishReload(w)
	case strings.Contains(line, "Configuration reload finished"):
		s.finishReload(w)
	}
}

// finishReload delivers the verdict; s.mu must be held.
func (s *Supervisor) finishReload(w *reloadWait) {
	s.reload = nil
	if w.failed {
		w.result <- &ReloadError{Detail: strings.Join(w.errs, "; ")}
		return
	}
	w.result <- nil
}

var tsPrefix = regexp.MustCompile(`^\[[^\]]*\]\s*`)

func stripTimestamp(line string) string { return tsPrefix.ReplaceAllString(line, "") }

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

// Apply validates conf, swaps it in atomically, signals syslog-ng to
// reload and waits for it to confirm. Only a confirmed config is archived
// (with its graph) in history. If syslog-ng refuses it at reload time the
// previous current.conf is restored and a *ReloadError returned. If
// syslog-ng isn't running at all, the config stays installed (so a crash
// loop on a bad config can be fixed by applying a good one), is archived,
// and an error wrapping ErrNotRunning is returned.
func (s *Supervisor) Apply(conf string, graphJSON []byte) error {
	if err := s.Validate(conf); err != nil {
		s.setErr(err)
		return err
	}
	prev, prevErr := os.ReadFile(s.ConfPath())
	if err := atomicWrite(s.ConfPath(), []byte(conf)); err != nil {
		return err
	}
	if err := s.Reload(); err != nil {
		if errors.Is(err, ErrNotRunning) {
			if aerr := s.archive(conf, graphJSON); aerr != nil {
				return aerr
			}
			s.kickLoop()
			return fmt.Errorf("config installed, but %w; it will be used when syslog-ng restarts", err)
		}
		// Put the old file back so a later cold start runs what syslog-ng
		// is actually still running.
		if prevErr == nil {
			if rerr := atomicWrite(s.ConfPath(), prev); rerr != nil {
				err = fmt.Errorf("%w (and restoring the previous config failed: %v)", err, rerr)
			}
			var re *ReloadError
			if !errors.As(err, &re) {
				// No verdict (timeout): make sure the running config
				// matches the restored file again.
				s.signal(syscall.SIGHUP)
			}
		}
		s.setErr(err)
		return err
	}
	return s.archive(conf, graphJSON)
}

func (s *Supervisor) archive(conf string, graphJSON []byte) error {
	id := time.Now().UTC().Format("20060102-150405.000")
	if err := atomicWrite(s.confFor(id), []byte(conf)); err != nil {
		return err
	}
	if err := atomicWrite(s.graphFor(id), graphJSON); err != nil {
		return err
	}
	s.prune()
	s.mu.Lock()
	s.lastApply = time.Now()
	s.lastErr = ""
	s.mu.Unlock()
	return nil
}

func (s *Supervisor) setErr(err error) {
	s.mu.Lock()
	s.lastErr = err.Error()
	s.mu.Unlock()
}

func (s *Supervisor) kickLoop() {
	select {
	case s.kick <- struct{}{}:
	default:
	}
}

// HistoryGraph returns the graph JSON archived with one history entry.
func (s *Supervisor) HistoryGraph(id string) ([]byte, error) {
	data, err := os.ReadFile(s.graphFor(id))
	if err != nil {
		return nil, fmt.Errorf("history entry %s: %w", id, err)
	}
	return data, nil
}

// ActiveGraph returns the graph JSON of the history entry whose config is
// the one currently installed, or ok=false when none matches (fresh
// install, or a config not produced by Apply).
func (s *Supervisor) ActiveGraph() (data []byte, id string, ok bool) {
	cur, err := os.ReadFile(s.ConfPath())
	if err != nil {
		return nil, "", false
	}
	for _, h := range s.History() {
		conf, err := os.ReadFile(s.confFor(h.ID))
		if err != nil || !bytes.Equal(conf, cur) {
			continue
		}
		data, err := os.ReadFile(s.graphFor(h.ID))
		if err != nil {
			return nil, "", false
		}
		return data, h.ID, true
	}
	return nil, "", false
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

// Reload sends SIGHUP (syslog-ng re-reads its config without dropping
// established TCP connections) and waits for syslog-ng to log the outcome.
// A config it refuses yields a *ReloadError; no verdict within
// ReloadTimeout is an error too.
func (s *Supervisor) Reload() error {
	s.mu.Lock()
	if s.cmd == nil || s.cmd.Process == nil {
		s.mu.Unlock()
		return ErrNotRunning
	}
	if s.reload != nil {
		s.mu.Unlock()
		return fmt.Errorf("another reload is in progress")
	}
	w := &reloadWait{result: make(chan error, 1)}
	s.reload = w
	if err := s.cmd.Process.Signal(syscall.SIGHUP); err != nil {
		s.reload = nil
		s.mu.Unlock()
		return err
	}
	timeout := s.ReloadTimeout
	s.mu.Unlock()

	t := time.NewTimer(timeout)
	defer t.Stop()
	select {
	case err := <-w.result:
		return err
	case <-t.C:
		s.mu.Lock()
		if s.reload == w {
			s.reload = nil
		}
		s.mu.Unlock()
		// The verdict may have raced the timer.
		select {
		case err := <-w.result:
			return err
		default:
		}
		return fmt.Errorf("syslog-ng did not confirm the reload within %s", timeout)
	}
}

func (s *Supervisor) signal(sig os.Signal) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cmd != nil && s.cmd.Process != nil {
		s.cmd.Process.Signal(sig)
	}
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
