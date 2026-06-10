// Package api serves the internal REST API consumed by the SPA, plus the
// SPA's static files and the live-tail WebSocket. No public API in v1
// (PLAN §3).
package api

import (
	"encoding/json"
	"errors"
	"io/fs"
	"log/slog"
	"net/http"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/syslog-yard/syslog-bucket/internal/engine"
	"github.com/syslog-yard/syslog-bucket/internal/rules"
	"github.com/syslog-yard/syslog-bucket/internal/store"
	"github.com/syslog-yard/syslog-bucket/internal/ws"
)

type server struct {
	store  *store.Store
	engine *engine.Engine
	hub    *ws.Hub
	web    fs.FS
	hints  map[string]string
}

func New(st *store.Store, eng *engine.Engine, hub *ws.Hub, web fs.FS, hints map[string]string) http.Handler {
	if hints == nil {
		hints = map[string]string{}
	}
	s := &server{store: st, engine: eng, hub: hub, web: web, hints: hints}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/healthz", s.healthz)
	mux.HandleFunc("GET /api/hints", s.getHints)
	mux.HandleFunc("GET /api/entries", s.listEntries)
	mux.HandleFunc("GET /api/entries/{id}", s.getEntry)
	mux.HandleFunc("PATCH /api/entries/{id}", s.patchEntry)
	mux.HandleFunc("PUT /api/entries/{id}/tags/{tag}", s.tagEntry)
	mux.HandleFunc("DELETE /api/entries/{id}/tags/{tag}", s.untagEntry)
	mux.HandleFunc("GET /api/sources", s.listSources)
	mux.HandleFunc("GET /api/stats", s.stats)
	mux.HandleFunc("GET /api/tags", s.listTags)
	mux.HandleFunc("POST /api/tags", s.createTag)
	mux.HandleFunc("PUT /api/tags/{id}", s.updateTag)
	mux.HandleFunc("DELETE /api/tags/{id}", s.deleteTag)
	mux.HandleFunc("GET /api/buckets", s.listBuckets)
	mux.HandleFunc("POST /api/buckets", s.createBucket)
	mux.HandleFunc("PUT /api/buckets/{id}", s.updateBucket)
	mux.HandleFunc("DELETE /api/buckets/{id}", s.deleteBucket)
	mux.HandleFunc("GET /api/rules", s.listRules)
	mux.HandleFunc("POST /api/rules", s.createRule)
	mux.HandleFunc("PUT /api/rules/{id}", s.updateRule)
	mux.HandleFunc("DELETE /api/rules/{id}", s.deleteRule)
	mux.HandleFunc("POST /api/rules/{id}/apply", s.applyRule)
	mux.HandleFunc("GET /api/ws", s.liveTail)
	mux.HandleFunc("GET /", s.spa)
	return mux
}

func (s *server) healthz(w http.ResponseWriter, r *http.Request) {
	if err := s.store.Pool.Ping(r.Context()); err != nil {
		http.Error(w, "database unreachable", http.StatusServiceUnavailable)
		return
	}
	writeJSON(w, map[string]string{"status": "ok"})
}

// getHints returns deployment-provided hints for the UI: links to the
// neighbor yard tools. Empty object when running standalone.
func (s *server) getHints(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, s.hints)
}

// condFromRequest translates the SPA's filter query parameters — plus an
// optional bucket — into one condition tree, the same grammar buckets and
// rules use (PLAN §5: one grammar, three uses).
func (s *server) condFromRequest(r *http.Request) (rules.Cond, error) {
	q := r.URL.Query()
	var all []rules.Cond

	if v := q.Get("bucket_id"); v != "" {
		id, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return rules.Cond{}, errors.New("bucket_id must be numeric")
		}
		b, err := s.store.GetBucket(r.Context(), id)
		if err != nil {
			return rules.Cond{}, err
		}
		if b == nil {
			return rules.Cond{}, errors.New("bucket not found")
		}
		all = append(all, b.Condition)
	}
	if v := q.Get("q"); v != "" {
		all = append(all, rules.Cond{Text: v})
	}
	for param, field := range map[string]string{"host": "host", "app": "app_name"} {
		if v := q.Get(param); v != "" {
			all = append(all, rules.Cond{Field: field, Op: "contains", Value: v})
		}
	}
	if v := q.Get("severity"); v != "" {
		n, err := strconv.ParseInt(v, 10, 16)
		if err != nil || n < 0 || n > 7 {
			return rules.Cond{}, errors.New("severity must be 0-7")
		}
		all = append(all, rules.Cond{Field: "severity", Op: "lte", Value: float64(n)})
	}
	for param, field := range map[string]string{"facility": "facility", "source_id": "source_id", "priority": "priority"} {
		if v := q.Get(param); v != "" {
			n, err := strconv.ParseInt(v, 10, 64)
			if err != nil {
				return rules.Cond{}, errors.New(param + " must be numeric")
			}
			all = append(all, rules.Cond{Field: field, Op: "eq", Value: float64(n)})
		}
	}
	if v := q.Get("status"); v != "" {
		all = append(all, rules.Cond{Field: "status", Op: "eq", Value: v})
	}
	if v := q.Get("tag_id"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return rules.Cond{}, errors.New("tag_id must be numeric")
		}
		all = append(all, rules.Cond{TagID: n})
	}
	for param, op := range map[string]string{"from": "gte", "to": "lte"} {
		if v := q.Get(param); v != "" {
			if _, err := time.Parse(time.RFC3339, v); err != nil {
				return rules.Cond{}, errors.New(param + " must be RFC3339")
			}
			all = append(all, rules.Cond{Field: "received_at", Op: op, Value: v})
		}
	}

	cond := rules.Cond{All: all}
	if err := cond.Validate(); err != nil {
		return rules.Cond{}, err
	}
	return cond, nil
}

func (s *server) listEntries(w http.ResponseWriter, r *http.Request) {
	cond, err := s.condFromRequest(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	q := r.URL.Query()
	f := store.EntryFilter{
		Cond:              cond,
		IncludeSuppressed: q.Get("include_suppressed") == "true",
	}
	for param, dst := range map[string]**int64{"before_id": &f.BeforeID, "after_id": &f.AfterID} {
		if v := q.Get(param); v != "" {
			n, err := strconv.ParseInt(v, 10, 64)
			if err != nil {
				http.Error(w, param+" must be numeric", http.StatusBadRequest)
				return
			}
			*dst = &n
		}
	}
	if v := q.Get("limit"); v != "" {
		f.Limit, _ = strconv.Atoi(v)
	}

	entries, err := s.store.ListEntries(r.Context(), f)
	if err != nil {
		s.internalError(w, "list entries", err)
		return
	}
	writeJSON(w, map[string]any{"entries": entries})
}

func (s *server) getEntry(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	entry, err := s.store.GetEntry(r.Context(), id)
	if err != nil {
		s.internalError(w, "get entry", err)
		return
	}
	if entry == nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	writeJSON(w, entry)
}

func (s *server) patchEntry(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	var patch struct {
		Status   *string `json:"status"`
		Priority *int16  `json:"priority"`
	}
	if !decodeJSON(w, r, &patch) {
		return
	}
	if patch.Status != nil && *patch.Status != "new" && *patch.Status != "reviewing" && *patch.Status != "resolved" {
		http.Error(w, "status must be new, reviewing, or resolved", http.StatusBadRequest)
		return
	}
	if patch.Priority != nil && (*patch.Priority < 0 || *patch.Priority > 3) {
		http.Error(w, "priority must be 0-3", http.StatusBadRequest)
		return
	}
	entry, err := s.store.UpdateEntry(r.Context(), id, patch.Status, patch.Priority)
	if err != nil {
		s.internalError(w, "update entry", err)
		return
	}
	if entry == nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	writeJSON(w, entry)
}

func (s *server) tagEntry(w http.ResponseWriter, r *http.Request)   { s.setEntryTag(w, r, true) }
func (s *server) untagEntry(w http.ResponseWriter, r *http.Request) { s.setEntryTag(w, r, false) }

func (s *server) setEntryTag(w http.ResponseWriter, r *http.Request, add bool) {
	entryID, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	tagID, ok := pathID(w, r, "tag")
	if !ok {
		return
	}
	var err error
	if add {
		err = s.store.TagEntry(r.Context(), entryID, tagID)
	} else {
		err = s.store.UntagEntry(r.Context(), entryID, tagID)
	}
	if err != nil {
		s.internalError(w, "tag entry", err)
		return
	}
	entry, err := s.store.GetEntry(r.Context(), entryID)
	if err != nil || entry == nil {
		s.internalError(w, "get entry after tag", err)
		return
	}
	writeJSON(w, entry)
}

func (s *server) listSources(w http.ResponseWriter, r *http.Request) {
	sources, err := s.store.ListSources(r.Context())
	if err != nil {
		s.internalError(w, "list sources", err)
		return
	}
	writeJSON(w, map[string]any{"sources": sources})
}

func (s *server) stats(w http.ResponseWriter, r *http.Request) {
	stats, err := s.store.GetStats(r.Context())
	if err != nil {
		s.internalError(w, "stats", err)
		return
	}
	writeJSON(w, stats)
}

func (s *server) liveTail(w http.ResponseWriter, r *http.Request) {
	cond, err := s.condFromRequest(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.hub.Serve(w, r, cond, r.URL.Query().Get("include_suppressed") == "true")
}

// spa serves the built frontend, falling back to index.html for client-side
// routes (anything without a file extension).
func (s *server) spa(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(path.Clean(r.URL.Path), "/")
	if name == "" {
		name = "index.html"
	}
	if _, err := fs.Stat(s.web, name); err != nil {
		if path.Ext(name) != "" {
			http.NotFound(w, r)
			return
		}
		name = "index.html"
	}
	http.ServeFileFS(w, r, s.web, name)
}

func (s *server) internalError(w http.ResponseWriter, what string, err error) {
	slog.Error("api: "+what, "error", err)
	http.Error(w, "internal error", http.StatusInternalServerError)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func pathID(w http.ResponseWriter, r *http.Request, name string) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue(name), 10, 64)
	if err != nil {
		http.Error(w, "invalid "+name, http.StatusBadRequest)
		return 0, false
	}
	return id, true
}

func decodeJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(v); err != nil {
		http.Error(w, "invalid JSON body: "+err.Error(), http.StatusBadRequest)
		return false
	}
	return true
}

// isUniqueViolation lets create/update handlers answer 409 for duplicate
// names instead of 500.
func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}
