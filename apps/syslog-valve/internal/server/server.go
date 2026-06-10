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

	"github.com/syslog-yard/syslog-valve/internal/codegen"
	"github.com/syslog-yard/syslog-valve/internal/graph"
	"github.com/syslog-yard/syslog-valve/internal/rotate"
	"github.com/syslog-yard/syslog-valve/internal/supervisor"
)

type Server struct {
	mux       *http.ServeMux
	sup       *supervisor.Supervisor
	graphPath string
	hints     map[string]string
	shares    codegen.Shares
	rotator   *rotate.Rotator
	mu        sync.Mutex // serializes graph writes and applies
}

func New(sup *supervisor.Supervisor, dataDir string, ui fs.FS, hints map[string]string, shares codegen.Shares, rotator *rotate.Rotator) *Server {
	s := &Server{
		mux:       http.NewServeMux(),
		sup:       sup,
		graphPath: filepath.Join(dataDir, "graph.json"),
		hints:     hints,
		shares:    shares,
		rotator:   rotator,
	}
	s.mux.HandleFunc("GET /api/graph", s.getGraph)
	s.mux.HandleFunc("PUT /api/graph", s.putGraph)
	s.mux.HandleFunc("POST /api/apply", s.apply)
	s.mux.HandleFunc("POST /api/rollback/{id}", s.rollback)
	s.mux.HandleFunc("GET /api/history", s.history)
	s.mux.HandleFunc("GET /api/config", s.config)
	s.mux.HandleFunc("GET /api/status", s.status)
	s.mux.HandleFunc("GET /api/hints", s.getHints)
	s.mux.HandleFunc("POST /api/rotate", s.rotateNow)
	s.mux.HandleFunc("GET /api/healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]string{"status": "ok"})
	})
	if ui != nil {
		s.mux.Handle("/", spaHandler(ui))
	}
	return s
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) { s.mux.ServeHTTP(w, r) }

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
// client-side routes.
func spaHandler(ui fs.FS) http.Handler {
	fileServer := http.FileServer(http.FS(ui))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := strings.TrimPrefix(r.URL.Path, "/")
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
