// Package server exposes the internal REST API and the embedded UI.
package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/syslog-yard/syslog-valve/internal/certs"
	"github.com/syslog-yard/syslog-valve/internal/codegen"
	"github.com/syslog-yard/syslog-valve/internal/graph"
	"github.com/syslog-yard/syslog-valve/internal/rotate"
	"github.com/syslog-yard/syslog-valve/internal/supervisor"
	"github.com/syslog-yard/syslog-valve/internal/tap"
	"github.com/syslog-yard/syslog-valve/internal/yardauth"
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
	mu        sync.Mutex // serializes graph writes and applies
}

// New builds the handler; guard enforces yard auth when YARD_AUTH_URL is
// set (nil = open, standalone mode).
func New(sup *supervisor.Supervisor, dataDir string, ui fs.FS, hints map[string]string, shares codegen.Shares, rotator *rotate.Rotator, tp *tap.Tap, guard *yardauth.Guard) *Server {
	s := &Server{
		mux:       http.NewServeMux(),
		sup:       sup,
		graphPath: filepath.Join(dataDir, "graph.json"),
		hints:     hints,
		shares:    shares,
		rotator:   rotator,
		tap:       tp,
	}
	s.mux.HandleFunc("GET /api/graph", s.getGraph)
	s.mux.HandleFunc("PUT /api/graph", s.putGraph)
	s.mux.HandleFunc("POST /api/apply", s.apply)
	s.mux.HandleFunc("POST /api/rollback/{id}", s.rollback)
	s.mux.HandleFunc("GET /api/history", s.history)
	s.mux.HandleFunc("GET /api/history/{id}/config", s.historyConfig)
	s.mux.HandleFunc("GET /api/config", s.config)
	s.mux.HandleFunc("GET /api/status", s.status)
	s.mux.HandleFunc("GET /api/hints", s.getHints)
	s.mux.HandleFunc("GET /api/certs", s.certStatus)
	s.mux.HandleFunc("POST /api/certs/selfsigned", s.certGenerate)
	s.mux.HandleFunc("GET /api/tail", s.tail)
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
	s.handler = guard.Middleware(s.mux)
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

// putGraph validates and saves the draft graph without applying it.
func (s *Server) putGraph(w http.ResponseWriter, r *http.Request) {
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
	if err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	if _, err := graph.Parse(data); err != nil {
		httpError(w, http.StatusUnprocessableEntity, err)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.WriteFile(s.graphPath, data, 0o644); err != nil {
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
	for _, n := range g.Nodes {
		if n.Type == graph.TypeSource && n.Config.Transport == "tls" {
			if err := certs.Require(codegen.CertFile, codegen.KeyFile); err != nil {
				httpError(w, http.StatusUnprocessableEntity, err)
				return
			}
			break
		}
	}
	conf, err := codegen.Generate(g, s.sup.Version(), s.shares)
	if err != nil {
		httpError(w, http.StatusUnprocessableEntity, err)
		return
	}
	lr, err := codegen.GenerateLogrotate(g, s.shares)
	if err != nil {
		httpError(w, http.StatusUnprocessableEntity, err)
		return
	}
	if err := s.sup.Apply(conf, data); err != nil {
		httpError(w, http.StatusUnprocessableEntity, fmt.Errorf("syslog-ng rejected the config: %w", err))
		return
	}
	if err := os.WriteFile(s.rotator.ConfPath, []byte(lr), 0o644); err != nil {
		httpError(w, http.StatusInternalServerError, fmt.Errorf("writing logrotate config: %w", err))
		return
	}
	writeJSON(w, map[string]any{"ok": true, "config": conf, "logrotate": lr})
}

func (s *Server) rollback(w http.ResponseWriter, r *http.Request) {
	if !validHistoryID(r.PathValue("id")) {
		httpError(w, http.StatusBadRequest, fmt.Errorf("invalid history id"))
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	graphJSON, err := s.sup.Rollback(r.PathValue("id"))
	if err != nil {
		httpError(w, http.StatusUnprocessableEntity, err)
		return
	}
	if err := os.WriteFile(s.graphPath, graphJSON, 0o644); err != nil {
		httpError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
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
	writeJSON(w, s.sup.Status())
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
