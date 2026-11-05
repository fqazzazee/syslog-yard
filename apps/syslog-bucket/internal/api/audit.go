package api

import (
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/syslog-yard/syslog-bucket/internal/audit"
	"github.com/syslog-yard/syslog-bucket/internal/auth"
	"github.com/syslog-yard/syslog-bucket/internal/store"
)

// record queues a successful action by the requesting user for the audit
// log. It never blocks or fails the request (see package audit). Summaries
// are built field by field from known-safe values: never pass a decoded
// request body, a channel config or a settings document here.
func (s *server) record(r *http.Request, action, targetType string, targetID any, summary map[string]any) {
	if s.auditor == nil {
		return
	}
	s.auditor.Record(audit.Event{
		ActorIP:    s.authSvc.ClientIP(r),
		Action:     action,
		TargetType: targetType,
		TargetID:   idString(targetID),
		Summary:    summary,
		Success:    true,
	}.As(auth.UserFrom(r.Context())))
}

func idString(v any) string {
	switch id := v.(type) {
	case nil:
		return ""
	case string:
		return id
	case int64:
		return strconv.FormatInt(id, 10)
	default:
		return fmt.Sprint(id)
	}
}

// change is a before/after pair for an update summary.
func change(from, to any) map[string]any { return map[string]any{"from": from, "to": to} }

// getAudit lists the audit log, newest first, for admins. Filters: actor
// (username, case-insensitive), action, target_type, target_id, success,
// since/until (RFC3339). Paging: pass the previous page's next_cursor as
// cursor; a null next_cursor means the last page.
func (s *server) getAudit(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	q := r.URL.Query()
	f := store.AuditFilter{
		Actor:      q.Get("actor"),
		Action:     q.Get("action"),
		TargetType: q.Get("target_type"),
		TargetID:   q.Get("target_id"),
	}
	for param, dst := range map[string]**time.Time{"since": &f.Since, "until": &f.Until} {
		if v := q.Get(param); v != "" {
			t, err := time.Parse(time.RFC3339, v)
			if err != nil {
				http.Error(w, param+" must be RFC3339", http.StatusBadRequest)
				return
			}
			*dst = &t
		}
	}
	if v := q.Get("actor_id"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			http.Error(w, "actor_id must be numeric", http.StatusBadRequest)
			return
		}
		f.ActorID = &n
	}
	if v := q.Get("success"); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			http.Error(w, "success must be true or false", http.StatusBadRequest)
			return
		}
		f.Success = &b
	}
	if v := q.Get("cursor"); v != "" {
		c, err := store.ParseAuditCursor(v)
		if err != nil {
			http.Error(w, "invalid cursor", http.StatusBadRequest)
			return
		}
		f.Before = &c
	}
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			http.Error(w, "limit must be a positive number", http.StatusBadRequest)
			return
		}
		f.Limit = n
	}
	events, next, err := s.store.ListAudit(r.Context(), f)
	if err != nil {
		s.internalError(w, "list audit log", err)
		return
	}
	var cursor *string
	if next != nil {
		c := next.String()
		cursor = &c
	}
	writeJSON(w, map[string]any{"events": events, "next_cursor": cursor})
}
