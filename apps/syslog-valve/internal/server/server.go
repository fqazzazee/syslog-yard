// Package server exposes the internal REST API and the embedded UI.
package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/syslog-yard/shared/secure"
	"github.com/syslog-yard/shared/yardauth"
	"github.com/syslog-yard/syslog-valve/internal/certs"
	"github.com/syslog-yard/syslog-valve/internal/codegen"
	"github.com/syslog-yard/syslog-valve/internal/graph"
	"github.com/syslog-yard/syslog-valve/internal/mitre"
	"github.com/syslog-yard/syslog-valve/internal/notify"
	"github.com/syslog-yard/syslog-valve/internal/rotate"
	"github.com/syslog-yard/syslog-valve/internal/supervisor"
	"github.com/syslog-yard/syslog-valve/internal/tap"
)

type Server struct {
	mux       *http.ServeMux
	handler   http.Handler
	sup       *supervisor.Supervisor
	graphPath string
	hints     map[string]string
	shares    codegen.Shares
	rotator   *rotate.Rotator
	tap       *tap.Tap
	notify    *notify.Dispatcher
	httpPort  int        // TCP port of this UI/API; sources may not take it
	mu        sync.Mutex // serializes graph writes and applies
}

// maxGraphBody caps a graph save. Every other mutating route takes
// secure.DefaultBodyLimit (64 KiB); bodyLimits applies both.
const maxGraphBody = 1 << 20

var bodyLimits = secure.BodyLimit{Routes: map[string]int64{
	"PUT /api/graph": maxGraphBody,
}}

// New builds the handler; guard enforces yard auth when YARD_AUTH_URL is
// set (nil = open, standalone mode).
func New(sup *supervisor.Supervisor, dataDir string, ui fs.FS, hints map[string]string, shares codegen.Shares, rotator *rotate.Rotator, tp *tap.Tap, nd *notify.Dispatcher, guard *yardauth.Guard) *Server {
	s := &Server{
		mux:       http.NewServeMux(),
		sup:       sup,
		graphPath: filepath.Join(dataDir, "graph.json"),
		hints:     hints,
		shares:    shares,
		rotator:   rotator,
		tap:       tp,
		notify:    nd,
	}
	s.syncActive()
	s.mux.HandleFunc("GET /api/graph", s.getGraph)
	s.mux.HandleFunc("PUT /api/graph", s.putGraph)
	s.mux.HandleFunc("POST /api/apply", s.apply)
	s.mux.HandleFunc("POST /api/rollback/{id}", s.rollback)
	s.mux.HandleFunc("GET /api/history", s.history)
	s.mux.HandleFunc("GET /api/history/{id}/config", s.historyConfig)
	s.mux.HandleFunc("GET /api/config", s.config)
	s.mux.HandleFunc("GET /api/status", s.status)
	s.mux.HandleFunc("GET /api/hints", s.getHints)
	s.mux.HandleFunc("GET /api/mitre", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, mitre.Get())
	})
	s.mux.HandleFunc("GET /api/certs", s.certStatus)
	s.mux.HandleFunc("POST /api/certs/selfsigned", s.certGenerate)
	s.mux.HandleFunc("GET /api/tail", s.tail)
	s.mux.HandleFunc("GET /api/notify/log", s.notifyLog)
	s.mux.HandleFunc("GET /api/notify/stats", s.notifyStats)
	s.mux.HandleFunc("POST /api/notify/test", s.notifyTest)
	s.mux.HandleFunc("POST /api/rotate", s.rotateNow)
	s.mux.HandleFunc("GET /api/healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]string{"status": "ok"})
	})
	if ui != nil {
		s.mux.Handle("/", spaHandler(ui))
	}
	if guard == nil {
		guard = yardauth.New("", false)
	}
	guard.Routes(s.mux)
	s.handler = secure.Headers(guard.Middleware(bodyLimits.Wrap(s.mux)))
	return s
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) { s.handler.ServeHTTP(w, r) }

func (s *Server) loadGraph() ([]byte, error) {
	data, err := os.ReadFile(s.graphPath)
	if errors.Is(err, os.ErrNotExist) {
		return []byte(`{"nodes":[],"edges":[]}`), nil
	}
	return data, err
}

func (s *Server) getGraph(w http.ResponseWriter, _ *http.Request) {
	data, err := s.loadGraph()
	if err != nil {
		httpError(w, http.StatusInternalServerError, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(data)
}

// SetHTTPPort records the TCP port the valve's own HTTP server listens on,
// so a graph can't put a syslog source on it.
func (s *Server) SetHTTPPort(port int) {
	s.mu.Lock()
	s.httpPort = port
	s.mu.Unlock()
}

// putGraph validates and saves the draft graph without applying it.
func (s *Server) putGraph(w http.ResponseWriter, r *http.Request) {
	data, err := io.ReadAll(r.Body) // capped by bodyLimits
	if err != nil {
		secure.WriteBodyError(w, err)
		return
	}
	g, err := graph.Parse(data)
	if err != nil {
		httpError(w, http.StatusUnprocessableEntity, err)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkDeployment(g); err != nil {
		httpError(w, http.StatusUnprocessableEntity, err)
		return
	}
	if err := atomicWrite(s.graphPath, data); err != nil {
		httpError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}

// apply compiles the saved graph and pushes it into syslog-ng.
func (s *Server) apply(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := s.loadGraph()
	if err != nil {
		httpError(w, http.StatusInternalServerError, err)
		return
	}
	g, err := graph.Parse(data)
	if err != nil {
		httpError(w, http.StatusUnprocessableEntity, err)
		return
	}
	act, err := s.activate(g, data)
	if err != nil {
		httpError(w, statusOf(err), err)
		return
	}
	resp := map[string]any{"ok": true, "config": act.config, "logrotate": act.logrotate}
	if act.warning != "" {
		resp["warning"] = act.warning
	}
	writeJSON(w, resp)
}

// rollback re-activates the graph archived with a history entry. It goes
// through the same path as apply (so codegen fixes and the current checks
// apply to it) and is recorded as a new history entry.
func (s *Server) rollback(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !validHistoryID(id) {
		httpError(w, http.StatusBadRequest, fmt.Errorf("invalid history id"))
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := s.sup.HistoryGraph(id)
	if err != nil {
		httpError(w, http.StatusNotFound, err)
		return
	}
	g, sanitized, err := graph.Load(data)
	if err != nil {
		httpError(w, http.StatusUnprocessableEntity, fmt.Errorf("history entry %s cannot be restored: %w", id, err))
		return
	}
	if sanitized {
		if data, err = json.Marshal(g); err != nil {
			httpError(w, http.StatusInternalServerError, err)
			return
		}
	}
	act, err := s.activate(g, data)
	if err != nil {
		httpError(w, statusOf(err), err)
		return
	}
	resp := map[string]any{"ok": true}
	if act.warning != "" {
		resp["warning"] = act.warning
	}
	writeJSON(w, resp)
}

type activation struct {
	config, logrotate string
	// warning is set when the config was installed but syslog-ng wasn't
	// running to confirm it.
	warning string
}

// statusError carries the HTTP status an activation failure maps to.
type statusError struct {
	code int
	err  error
}

func (e *statusError) Error() string { return e.err.Error() }
func (e *statusError) Unwrap() error { return e.err }

func fail(code int, err error) error { return &statusError{code: code, err: err} }

func statusOf(err error) int {
	var se *statusError
	if errors.As(err, &se) {
		return se.code
	}
	return http.StatusInternalServerError
}

// checkDeployment runs the checks that depend on this process rather than
// the graph alone. Callers hold s.mu.
func (s *Server) checkDeployment(g *graph.Graph) error {
	return g.CheckReservedPort("tcp", s.httpPort, "the valve web UI")
}

// activate is the single path that makes a validated graph the running
// flow, used by apply and rollback: compile it, have syslog-ng load and
// confirm it, then bring everything derived from the applied graph in line
// (logrotate.conf, notify targets) and save it as the draft. Nothing is
// touched unless syslog-ng accepted the config. Callers hold s.mu.
func (s *Server) activate(g *graph.Graph, data []byte) (*activation, error) {
	if err := s.checkDeployment(g); err != nil {
		return nil, fail(http.StatusUnprocessableEntity, err)
	}
	for _, n := range g.Enabled().Nodes {
		if n.Type == graph.TypeSource && n.Config.Transport == "tls" {
			if err := certs.Require(codegen.CertFile, codegen.KeyFile); err != nil {
				return nil, fail(http.StatusUnprocessableEntity, err)
			}
			break
		}
	}
	conf, err := codegen.Generate(g, s.sup.Version(), s.shares)
	if err != nil {
		return nil, fail(http.StatusUnprocessableEntity, err)
	}
	lr, err := codegen.GenerateLogrotate(g, s.shares)
	if err != nil {
		return nil, fail(http.StatusUnprocessableEntity, err)
	}
	act := &activation{config: conf, logrotate: lr}
	if err := s.sup.Apply(conf, data); err != nil {
		var re *supervisor.ReloadError
		switch {
		case errors.Is(err, supervisor.ErrNotRunning):
			act.warning = err.Error()
		case errors.As(err, &re):
			return nil, fail(http.StatusUnprocessableEntity, err)
		default:
			return nil, fail(http.StatusUnprocessableEntity, fmt.Errorf("syslog-ng rejected the config: %w", err))
		}
	}
	if err := s.syncDerived(g, lr); err != nil {
		return nil, fail(http.StatusInternalServerError, err)
	}
	if err := atomicWrite(s.graphPath, data); err != nil {
		return nil, fail(http.StatusInternalServerError, fmt.Errorf("saving graph: %w", err))
	}
	return act, nil
}

// syncDerived points logrotate and the notify dispatcher at the applied
// graph.
func (s *Server) syncDerived(g *graph.Graph, logrotate string) error {
	if s.rotator != nil {
		if err := atomicWrite(s.rotator.ConfPath, []byte(logrotate)); err != nil {
			return fmt.Errorf("writing logrotate config: %w", err)
		}
	}
	if s.notify != nil {
		s.notify.SetGraph(g)
	}
	return nil
}

// syncActive runs at startup: it regenerates logrotate.conf and the notify
// targets from the graph archived with the config syslog-ng is running, so
// they match it even if an older version wrote them. A stored graph that
// fails today's validation is sanitized and used anyway (codegen escapes
// on its own) — it must never keep the valve from starting.
func (s *Server) syncActive() {
	data, id, ok := s.sup.ActiveGraph()
	if !ok {
		// Nothing applied through the valve matches the running config
		// (fresh install). Seed notify targets from the saved draft, as
		// before, and leave logrotate.conf alone.
		if s.notify == nil {
			return
		}
		if data, err := s.loadGraph(); err == nil {
			if g, _, err := graph.Decode(data); err == nil {
				s.notify.SetGraph(g)
			}
		}
		return
	}
	g, sanitized, err := graph.Decode(data)
	if err != nil {
		slog.Warn("active graph unreadable; logrotate config and notify targets not refreshed", "history", id, "err", err)
		return
	}
	if sanitized {
		slog.Warn("active graph contained control characters; sanitized them", "history", id)
	}
	if err := g.Validate(); err != nil {
		slog.Warn("active graph fails current validation; re-apply after fixing it", "history", id, "err", err)
	}
	lr, err := codegen.GenerateLogrotate(g, s.shares)
	if err != nil {
		// e.g. a share that is no longer mounted. The existing file stays:
		// an old one could only carry injected directives via line breaks
		// in a dir, and those are sanitized above, so regenerating such a
		// graph succeeds and overwrites it.
		slog.Warn("cannot regenerate logrotate config; keeping the existing one", "err", err)
		if s.notify != nil {
			s.notify.SetGraph(g)
		}
		return
	}
	if err := s.syncDerived(g, lr); err != nil {
		slog.Warn("startup sync", "err", err)
	}
}

func atomicWrite(path string, data []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func (s *Server) history(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, s.sup.History())
}

// historyConfig returns the archived syslog-ng config for one history
// entry, so the UI can preview a version before rolling back.
func (s *Server) historyConfig(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !validHistoryID(id) {
		httpError(w, http.StatusBadRequest, fmt.Errorf("invalid history id"))
		return
	}
	data, err := s.sup.HistoryConfig(id)
	if err != nil {
		httpError(w, http.StatusNotFound, err)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write(data)
}

// History ids are supervisor-issued timestamps; anything else (path
// separators in particular) is rejected before touching the filesystem.
func validHistoryID(id string) bool {
	if id == "" {
		return false
	}
	for _, r := range id {
		if (r < '0' || r > '9') && r != '-' && r != '.' {
			return false
		}
	}
	return true
}

func (s *Server) config(w http.ResponseWriter, _ *http.Request) {
	data, err := os.ReadFile(s.sup.ConfPath())
	if err != nil {
		httpError(w, http.StatusInternalServerError, err)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write(data)
}

func (s *Server) status(w http.ResponseWriter, _ *http.Request) {
	st := s.sup.Status()
	resp := struct {
		supervisor.Status
		Throughput map[string]int64 `json:"throughput,omitempty"`
	}{Status: st}
	// Per-node processed counters for the wire labels; cheap enough to read on
	// each poll, and only meaningful while syslog-ng is up.
	if st.Running {
		if stats, err := s.sup.Stats(); err == nil {
			resp.Throughput = s.throughputByNode(stats)
		}
	}
	writeJSON(w, resp)
}

// throughputByNode maps syslog-ng's per-statement processed counters back to
// graph node IDs (sources and sinks; filters have no driver counter).
func (s *Server) throughputByNode(stats map[string]int64) map[string]int64 {
	data, err := s.loadGraph()
	if err != nil {
		return nil
	}
	var g graph.Graph
	if json.Unmarshal(data, &g) != nil {
		return nil
	}
	out := map[string]int64{}
	for _, n := range g.Nodes {
		var key string
		switch n.Type {
		case graph.TypeSource:
			key = "s_" + graph.Ident(n.ID)
		case graph.TypeForward, graph.TypeCache, graph.TypeNotify:
			key = "d_" + graph.Ident(n.ID)
		default:
			continue
		}
		if v, ok := stats[key]; ok {
			out[n.ID] = v
		}
	}
	return out
}

func (s *Server) getHints(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, s.hints)
}

func (s *Server) certStatus(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, certs.Inspect(codegen.CertFile))
}

// certGenerate (re)creates the valve's self-signed TLS identity. SANs
// cover the suite-internal name plus loopback; deployments needing real
// names mount their own pair instead.
func (s *Server) certGenerate(w http.ResponseWriter, _ *http.Request) {
	hosts := []string{"syslog-valve", "localhost", "127.0.0.1"}
	if hn, err := os.Hostname(); err == nil && hn != "" {
		hosts = append(hosts, hn)
	}
	if err := certs.GenerateSelfSigned(codegen.CertFile, codegen.KeyFile, hosts); err != nil {
		httpError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, certs.Inspect(codegen.CertFile))
}

// tail streams tap events as SSE: a replay of the recent ring, then live.
func (s *Server) tail(w http.ResponseWriter, r *http.Request) {
	fl, ok := w.(http.Flusher)
	if !ok {
		httpError(w, http.StatusInternalServerError, fmt.Errorf("streaming unsupported"))
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	replay, ch, cancel := s.tap.Subscribe()
	defer cancel()
	send := func(ev tap.Event) bool {
		payload, _ := json.Marshal(ev)
		if _, err := fmt.Fprintf(w, "data: %s\n\n", payload); err != nil {
			return false
		}
		fl.Flush()
		return true
	}
	for _, ev := range replay {
		if !send(ev) {
			return
		}
	}
	for {
		select {
		case <-r.Context().Done():
			return
		case ev := <-ch:
			if !send(ev) {
				return
			}
		}
	}
}

func (s *Server) rotateNow(w http.ResponseWriter, _ *http.Request) {
	out, err := s.rotator.Run()
	if err != nil {
		httpError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, map[string]string{"result": out})
}

// notifyLog returns the recent notification deliveries (in-memory ring).
func (s *Server) notifyLog(w http.ResponseWriter, _ *http.Request) {
	if s.notify == nil {
		writeJSON(w, []any{})
		return
	}
	writeJSON(w, s.notify.Recent())
}

// notifyStats returns per-notify-node delivery counters (sent, failed,
// dropped), keyed by node ident.
func (s *Server) notifyStats(w http.ResponseWriter, _ *http.Request) {
	if s.notify == nil {
		writeJSON(w, map[string]any{})
		return
	}
	writeJSON(w, s.notify.Stats())
}

// notifyTest delivers a synthetic notification to a channel config so the user
// can confirm wiring before applying the graph.
func (s *Server) notifyTest(w http.ResponseWriter, r *http.Request) {
	if s.notify == nil {
		httpError(w, http.StatusServiceUnavailable, fmt.Errorf("notifications disabled"))
		return
	}
	var body struct {
		Kind string `json:"kind"`
		URL  string `json:"url"`
	}
	data, err := io.ReadAll(r.Body) // capped by bodyLimits
	if err != nil {
		secure.WriteBodyError(w, err)
		return
	}
	if err := json.Unmarshal(data, &body); err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	if body.Kind != "webhook" && body.Kind != "slack" {
		httpError(w, http.StatusBadRequest, fmt.Errorf("kind must be webhook or slack"))
		return
	}
	if err := graph.CheckNotifyURL(body.URL); err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	if err := s.notify.TestSend(r.Context(), body.Kind, body.URL); err != nil {
		httpError(w, http.StatusBadGateway, err)
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func httpError(w http.ResponseWriter, code int, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
}

// spaHandler serves the embedded UI, falling back to index.html for
// client-side routes. Hashed assets cache forever; index.html must
// revalidate, or a browser that cached it before an image update keeps
// requesting bundles that no longer exist.
func spaHandler(ui fs.FS) http.Handler {
	fileServer := http.FileServer(http.FS(ui))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := strings.TrimPrefix(r.URL.Path, "/")
		if strings.HasPrefix(p, "assets/") {
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		} else {
			w.Header().Set("Cache-Control", "no-cache")
		}
		if p != "" {
			if f, err := ui.Open(p); err == nil {
				f.Close()
				fileServer.ServeHTTP(w, r)
				return
			}
		}
		r.URL.Path = "/"
		fileServer.ServeHTTP(w, r)
	})
}
