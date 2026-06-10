package api

import (
	"log/slog"
	"net/http"
	"strings"

	"github.com/syslog-yard/syslog-bucket/internal/auth"
	"github.com/syslog-yard/syslog-bucket/internal/rules"
	"github.com/syslog-yard/syslog-bucket/internal/store"
)

// --- tags ---

func (s *server) listTags(w http.ResponseWriter, r *http.Request) {
	tags, err := s.store.ListTags(r.Context())
	if err != nil {
		s.internalError(w, "list tags", err)
		return
	}
	writeJSON(w, map[string]any{"tags": tags})
}

func (s *server) createTag(w http.ResponseWriter, r *http.Request) {
	var t store.Tag
	if !decodeJSON(w, r, &t) || !validTag(w, t) {
		return
	}
	created, err := s.store.CreateTag(r.Context(), t)
	if err != nil {
		s.writeError(w, "create tag", err)
		return
	}
	writeJSON(w, created)
}

func (s *server) updateTag(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	var t store.Tag
	if !decodeJSON(w, r, &t) || !validTag(w, t) {
		return
	}
	t.ID = id
	found, err := s.store.UpdateTag(r.Context(), t)
	if err != nil {
		s.writeError(w, "update tag", err)
		return
	}
	if !found {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	writeJSON(w, t)
}

func (s *server) deleteTag(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	if err := s.store.DeleteTag(r.Context(), id); err != nil {
		s.internalError(w, "delete tag", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func validTag(w http.ResponseWriter, t store.Tag) bool {
	if strings.TrimSpace(t.Name) == "" {
		http.Error(w, "tag name required", http.StatusBadRequest)
		return false
	}
	return true
}

// --- buckets ---
//
// Visibility and edit rights follow PLAN §7: owners and admins manage a
// bucket, shares grant view or edit, ownerless buckets belong to the yard.

func (s *server) listBuckets(w http.ResponseWriter, r *http.Request) {
	buckets, err := s.store.ListBuckets(r.Context(), auth.UserFrom(r.Context()))
	if err != nil {
		s.internalError(w, "list buckets", err)
		return
	}
	writeJSON(w, map[string]any{"buckets": buckets})
}

func (s *server) createBucket(w http.ResponseWriter, r *http.Request) {
	var b store.Bucket
	if !decodeJSON(w, r, &b) || !validBucket(w, b) {
		return
	}
	u := auth.UserFrom(r.Context())
	b.OwnerID = &u.ID
	b.OwnerName = u.Username
	created, err := s.store.CreateBucket(r.Context(), b)
	if err != nil {
		s.writeError(w, "create bucket", err)
		return
	}
	writeJSON(w, created)
}

// visibleBucket loads a bucket as the requesting user sees it, answering
// 404 for both "absent" and "not yours to see".
func (s *server) visibleBucket(w http.ResponseWriter, r *http.Request) *store.Bucket {
	id, ok := pathID(w, r, "id")
	if !ok {
		return nil
	}
	b, err := s.store.GetBucket(r.Context(), id, auth.UserFrom(r.Context()))
	if err != nil {
		s.internalError(w, "get bucket", err)
		return nil
	}
	if b == nil {
		http.Error(w, "not found", http.StatusNotFound)
		return nil
	}
	return b
}

func (s *server) updateBucket(w http.ResponseWriter, r *http.Request) {
	existing := s.visibleBucket(w, r)
	if existing == nil {
		return
	}
	if !existing.CanEdit {
		http.Error(w, "you cannot edit this bucket", http.StatusForbidden)
		return
	}
	var b store.Bucket
	if !decodeJSON(w, r, &b) || !validBucket(w, b) {
		return
	}
	b.ID = existing.ID
	if _, err := s.store.UpdateBucket(r.Context(), b); err != nil {
		s.writeError(w, "update bucket", err)
		return
	}
	b.OwnerID, b.OwnerName, b.CanEdit, b.Shared = existing.OwnerID, existing.OwnerName, true, existing.Shared
	writeJSON(w, b)
}

func (s *server) deleteBucket(w http.ResponseWriter, r *http.Request) {
	b := s.visibleBucket(w, r)
	if b == nil {
		return
	}
	if !canManageBucket(auth.UserFrom(r.Context()), b) {
		http.Error(w, "only the owner or an admin can delete this bucket", http.StatusForbidden)
		return
	}
	if err := s.store.DeleteBucket(r.Context(), b.ID); err != nil {
		s.internalError(w, "delete bucket", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// canManageBucket gates delete and sharing: admins, the owner, or any
// analyst for ownerless yard buckets. Edit-shares deliberately do not
// qualify — sharing doesn't transfer control.
func canManageBucket(u *store.User, b *store.Bucket) bool {
	if u.Role == store.RoleAdmin {
		return true
	}
	if b.OwnerID == nil {
		return u.Role == store.RoleAnalyst
	}
	return *b.OwnerID == u.ID
}

func validBucket(w http.ResponseWriter, b store.Bucket) bool {
	if strings.TrimSpace(b.Name) == "" {
		http.Error(w, "bucket name required", http.StatusBadRequest)
		return false
	}
	if err := b.Condition.Validate(); err != nil {
		http.Error(w, "condition: "+err.Error(), http.StatusBadRequest)
		return false
	}
	return true
}

// --- rules ---

func (s *server) listRules(w http.ResponseWriter, r *http.Request) {
	list, err := s.store.ListRules(r.Context())
	if err != nil {
		s.internalError(w, "list rules", err)
		return
	}
	writeJSON(w, map[string]any{"rules": list})
}

func (s *server) createRule(w http.ResponseWriter, r *http.Request) {
	var rule store.Rule
	if !decodeJSON(w, r, &rule) || !validRule(w, rule) {
		return
	}
	created, err := s.store.CreateRule(r.Context(), rule)
	if err != nil {
		s.writeError(w, "create rule", err)
		return
	}
	s.reloadEngine(r)
	writeJSON(w, created)
}

func (s *server) updateRule(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	var rule store.Rule
	if !decodeJSON(w, r, &rule) || !validRule(w, rule) {
		return
	}
	rule.ID = id
	found, err := s.store.UpdateRule(r.Context(), rule)
	if err != nil {
		s.writeError(w, "update rule", err)
		return
	}
	if !found {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	s.reloadEngine(r)
	writeJSON(w, rule)
}

func (s *server) deleteRule(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	if err := s.store.DeleteRule(r.Context(), id); err != nil {
		s.internalError(w, "delete rule", err)
		return
	}
	s.reloadEngine(r)
	w.WriteHeader(http.StatusNoContent)
}

// applyRule runs a rule against historical entries — the retroactive power
// of virtual buckets (PLAN §5).
func (s *server) applyRule(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	rule, err := s.store.GetRule(r.Context(), id)
	if err != nil {
		s.internalError(w, "get rule", err)
		return
	}
	if rule == nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	affected, err := s.store.ApplyRuleHistorical(r.Context(), *rule)
	if err != nil {
		s.internalError(w, "apply rule", err)
		return
	}
	writeJSON(w, map[string]int64{"affected": affected})
}

func validRule(w http.ResponseWriter, rule store.Rule) bool {
	if strings.TrimSpace(rule.Name) == "" {
		http.Error(w, "rule name required", http.StatusBadRequest)
		return false
	}
	if err := rule.Condition.Validate(); err != nil {
		http.Error(w, "condition: "+err.Error(), http.StatusBadRequest)
		return false
	}
	if err := rules.ValidateActions(rule.Actions); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return false
	}
	return true
}

func (s *server) reloadEngine(r *http.Request) {
	if err := s.engine.Reload(r.Context()); err != nil {
		slog.Error("api: reload rules engine", "error", err)
	}
}

// writeError maps unique-name collisions to 409 and everything else to 500.
func (s *server) writeError(w http.ResponseWriter, what string, err error) {
	if isUniqueViolation(err) {
		http.Error(w, "name already in use", http.StatusConflict)
		return
	}
	s.internalError(w, what, err)
}
