// Package server exposes the internal REST API, the SSE stream and the
// embedded web UI.
package server

import (
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"strings"
	"time"

	"github.com/tesla/syshose/internal/engine"
	"github.com/tesla/syshose/internal/preset"
)

// Server wires the manager and preset store into an http.Handler.
type Server struct {
	mgr   *engine.Manager
	store *preset.Store
	ui    fs.FS
	mux   *http.ServeMux
}

// New builds the handler. ui is the built web app (may be nil in tests).
func New(mgr *engine.Manager, store *preset.Store, ui fs.FS) *Server {
	s := &Server{mgr: mgr, store: store, ui: ui, mux: http.NewServeMux()}
	s.routes()
	return s
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) { s.mux.ServeHTTP(w, r) }

func (s *Server) routes() {
	s.mux.HandleFunc("GET /api/jobs", s.listJobs)
	s.mux.HandleFunc("POST /api/jobs", s.createJob)
	s.mux.HandleFunc("PUT /api/jobs/{id}", s.updateJob)
	s.mux.HandleFunc("DELETE /api/jobs/{id}", s.deleteJob)
	s.mux.HandleFunc("POST /api/jobs/{id}/start", s.startJob)
	s.mux.HandleFunc("POST /api/jobs/{id}/stop", s.stopJob)
	s.mux.HandleFunc("POST /api/jobs/stop-all", s.stopAll)
	s.mux.HandleFunc("GET /api/presets", s.listPresets)
	s.mux.HandleFunc("GET /api/presets/{name}", s.getPreset)
	s.mux.HandleFunc("POST /api/presets", s.savePreset)
	s.mux.HandleFunc("DELETE /api/presets/{name}", s.deletePreset)
	s.mux.HandleFunc("POST /api/preview", s.preview)
	s.mux.HandleFunc("GET /api/stream", s.stream)
	if s.ui != nil {
		s.mux.Handle("/", spaHandler(s.ui))
	}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, err error) {
	writeJSON(w, code, map[string]string{"error": err.Error()})
}

// --- jobs ---

func (s *Server) listJobs(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, s.mgr.List())
}

func (s *Server) createJob(w http.ResponseWriter, r *http.Request) {
	var cfg engine.JobConfig
	if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
		writeErr(w, 400, err)
		return
	}
	st, err := s.mgr.Create(cfg)
	if err != nil {
		writeErr(w, 400, err)
		return
	}
	writeJSON(w, 201, st)
}

func (s *Server) updateJob(w http.ResponseWriter, r *http.Request) {
	var cfg engine.JobConfig
	if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
		writeErr(w, 400, err)
		return
	}
	st, err := s.mgr.Update(r.PathValue("id"), cfg)
	if err != nil {
		writeErr(w, 400, err)
		return
	}
	writeJSON(w, 200, st)
}

func (s *Server) deleteJob(w http.ResponseWriter, r *http.Request) {
	if err := s.mgr.Delete(r.PathValue("id")); err != nil {
		writeErr(w, 404, err)
		return
	}
	w.WriteHeader(204)
}

func (s *Server) startJob(w http.ResponseWriter, r *http.Request) {
	if err := s.mgr.Start(r.PathValue("id")); err != nil {
		writeErr(w, 400, err)
		return
	}
	w.WriteHeader(204)
}

func (s *Server) stopJob(w http.ResponseWriter, r *http.Request) {
	if err := s.mgr.Stop(r.PathValue("id")); err != nil {
		writeErr(w, 400, err)
		return
	}
	w.WriteHeader(204)
}

func (s *Server) stopAll(w http.ResponseWriter, r *http.Request) {
	s.mgr.StopAll()
	w.WriteHeader(204)
}

// --- presets ---

type presetSummary struct {
	Name        string `json:"name"`
	Vendor      string `json:"vendor"`
	Description string `json:"description"`
	Format      string `json:"format"`
	Builtin     bool   `json:"builtin"`
	EventCount  int    `json:"eventCount"`
}

func (s *Server) listPresets(w http.ResponseWriter, r *http.Request) {
	all := s.store.List()
	out := make([]presetSummary, 0, len(all))
	for _, p := range all {
		out = append(out, presetSummary{
			Name: p.Name, Vendor: p.Vendor, Description: p.Description,
			Format: p.Format, Builtin: p.Builtin, EventCount: len(p.Events),
		})
	}
	writeJSON(w, 200, out)
}

func (s *Server) getPreset(w http.ResponseWriter, r *http.Request) {
	p, ok := s.store.Get(r.PathValue("name"))
	if !ok {
		writeErr(w, 404, fmt.Errorf("preset not found"))
		return
	}
	raw, err := p.YAML()
	if err != nil {
		writeErr(w, 500, err)
		return
	}
	writeJSON(w, 200, map[string]any{
		"name": p.Name, "builtin": p.Builtin, "yaml": string(raw),
	})
}

func (s *Server) savePreset(w http.ResponseWriter, r *http.Request) {
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
	if err != nil {
		writeErr(w, 400, err)
		return
	}
	p, err := s.store.Save(raw)
	if err != nil {
		writeErr(w, 400, err)
		return
	}
	writeJSON(w, 201, map[string]string{"name": p.Name})
}

func (s *Server) deletePreset(w http.ResponseWriter, r *http.Request) {
	if err := s.store.Delete(r.PathValue("name")); err != nil {
		writeErr(w, 400, err)
		return
	}
	w.WriteHeader(204)
}

// preview renders sample events from either a stored preset ("preset") or
// an inline YAML definition ("yaml"), without sending anything.
func (s *Server) preview(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Preset   string `json:"preset"`
		YAML     string `json:"yaml"`
		Count    int    `json:"count"`
		Hostname string `json:"hostname"`
		Appname  string `json:"appname"`
		Format   string `json:"format"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, 400, err)
		return
	}
	var p *preset.Preset
	if req.YAML != "" {
		var err error
		if p, err = preset.Parse([]byte(req.YAML)); err != nil {
			writeErr(w, 400, err)
			return
		}
	} else {
		var ok bool
		if p, ok = s.store.Get(req.Preset); !ok {
			writeErr(w, 404, fmt.Errorf("preset %q not found", req.Preset))
			return
		}
	}
	if req.Count < 1 || req.Count > 50 {
		req.Count = 5
	}
	rend := p.NewRenderer(preset.RenderOpts{
		Hostname: req.Hostname, Appname: req.Appname, Facility: -1, Format: req.Format,
	})
	samples := make([]string, 0, req.Count)
	for i := 0; i < req.Count; i++ {
		msg, err := rend.Render()
		if err != nil {
			writeErr(w, 400, err)
			return
		}
		samples = append(samples, msg)
	}
	writeJSON(w, 200, map[string]any{"samples": samples})
}

// --- SSE stream: job stats + live tail ---

func (s *Server) stream(w http.ResponseWriter, r *http.Request) {
	fl, ok := w.(http.Flusher)
	if !ok {
		writeErr(w, 500, fmt.Errorf("streaming unsupported"))
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	var cursor int64
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	send := func() bool {
		events := s.mgr.TailSince(cursor)
		if len(events) > 0 {
			cursor = events[len(events)-1].Seq
		}
		payload, _ := json.Marshal(map[string]any{
			"jobs":   s.mgr.List(),
			"events": events,
		})
		if _, err := fmt.Fprintf(w, "data: %s\n\n", payload); err != nil {
			return false
		}
		fl.Flush()
		return true
	}
	if !send() {
		return
	}
	for {
		select {
		case <-r.Context().Done():
			return
		case <-tick.C:
			if !send() {
				return
			}
		}
	}
}

// spaHandler serves the embedded UI, falling back to index.html for
// client-side routes.
func spaHandler(ui fs.FS) http.Handler {
	fileServer := http.FileServer(http.FS(ui))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/")
		if path != "" {
			if f, err := ui.Open(path); err == nil {
				f.Close()
				fileServer.ServeHTTP(w, r)
				return
			}
		}
		r.URL.Path = "/"
		fileServer.ServeHTTP(w, r)
	})
}
