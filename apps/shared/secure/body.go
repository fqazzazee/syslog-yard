package secure

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
)

// DefaultBodyLimit caps the request body of a state-changing route that
// has no override in BodyLimit.Routes. Job configs, channel tests and
// logins are a few hundred bytes to a few KiB.
const DefaultBodyLimit = 64 << 10

// BodyLimit caps the request body of every POST/PUT/PATCH/DELETE served
// by one ServeMux, so each yard tool answers an oversized body the same
// way: 413 with {"error": "..."}. Routes raises (or lowers) the cap for
// individual routes, keyed by the exact pattern they were registered
// with, e.g. "PUT /api/graph".
type BodyLimit struct {
	Default int64            // 0 = DefaultBodyLimit
	Routes  map[string]int64 // per-pattern overrides
}

// Wrap returns mux with the caps applied. A body whose declared
// Content-Length is over the cap is refused before the handler runs,
// even on routes that never read a body. A body of unknown length is
// wrapped in http.MaxBytesReader; handlers that read it pass a read error
// to WriteBodyError, which turns the cap into the same 413.
func (b BodyLimit) Wrap(mux *http.ServeMux) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if stateChanging(r.Method) && r.Body != nil && r.Body != http.NoBody {
			limit := b.limitFor(mux, r)
			if r.ContentLength > limit {
				writeTooLarge(w, limit)
				return
			}
			r.Body = http.MaxBytesReader(w, r.Body, limit)
		}
		mux.ServeHTTP(w, r)
	})
}

func (b BodyLimit) limitFor(mux *http.ServeMux, r *http.Request) int64 {
	if _, pattern := mux.Handler(r); pattern != "" {
		if n, ok := b.Routes[pattern]; ok {
			return n
		}
	}
	if b.Default > 0 {
		return b.Default
	}
	return DefaultBodyLimit
}

// WriteBodyError answers a failed body read or decode: 413 when the body
// went over its cap, else 400. Both carry {"error": "..."}.
func WriteBodyError(w http.ResponseWriter, err error) {
	var tooBig *http.MaxBytesError
	if errors.As(err, &tooBig) {
		writeTooLarge(w, tooBig.Limit)
		return
	}
	writeError(w, http.StatusBadRequest, err.Error())
}

func writeTooLarge(w http.ResponseWriter, limit int64) {
	writeError(w, http.StatusRequestEntityTooLarge, fmt.Sprintf("request body larger than %d bytes", limit))
}

func writeError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
