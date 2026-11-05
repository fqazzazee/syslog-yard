package api

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/syslog-yard/syslog-bucket/internal/audit"
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
	s.record(r, audit.TagCreate, "tag", created.ID, map[string]any{"name": created.Name})
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
	s.record(r, audit.TagUpdate, "tag", id, map[string]any{"name": t.Name})
	writeJSON(w, t)
}

func (s *server) deleteTag(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	name := s.tagName(r, id)
	if err := s.store.DeleteTag(r.Context(), id); err != nil {
		if errors.Is(err, store.ErrInUse) {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		s.internalError(w, "delete tag", err)
		return
	}
	s.record(r, audit.TagDelete, "tag", id, map[string]any{"name": name})
	w.WriteHeader(http.StatusNoContent)
}

// tagName looks a tag's name up for an audit row (best effort: "" if gone).
func (s *server) tagName(r *http.Request, id int64) string {
	tags, err := s.store.ListTags(r.Context())
	if err != nil {
		return ""
	}
	for _, t := range tags {
		if t.ID == id {
			return t.Name
		}
	}
	return ""
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
// Visibility and edit rights: owners and admins manage a
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
	s.record(r, audit.BucketCreate, "bucket", created.ID, map[string]any{"name": created.Name})
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
	sum := map[string]any{"name": b.Name}
	if b.Name != existing.Name {
		sum["renamed_from"] = existing.Name
	}
	s.record(r, audit.BucketUpdate, "bucket", b.ID, sum)
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
	s.record(r, audit.BucketDelete, "bucket", b.ID, map[string]any{"name": b.Name})
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
	if !decodeJSON(w, r, &rule) || !validRule(w, rule) || !s.ruleRefsExist(w, r, rule) {
		return
	}
	created, err := s.store.CreateRule(r.Context(), rule)
	if err != nil {
		s.writeError(w, "create rule", err)
		return
	}
	s.record(r, audit.RuleCreate, "rule", created.ID, ruleSummary(created))
	s.reloadEngine(r)
	writeJSON(w, created)
}

func (s *server) updateRule(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	var rule store.Rule
	if !decodeJSON(w, r, &rule) || !validRule(w, rule) || !s.ruleRefsExist(w, r, rule) {
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
	s.record(r, audit.RuleUpdate, "rule", id, ruleSummary(rule))
	s.reloadEngine(r)
	writeJSON(w, rule)
}

func (s *server) deleteRule(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	gone, err := s.store.GetRule(r.Context(), id)
	if err != nil {
		s.internalError(w, "get rule", err)
		return
	}
	if err := s.store.DeleteRule(r.Context(), id); err != nil {
		s.internalError(w, "delete rule", err)
		return
	}
	if gone != nil {
		s.record(r, audit.RuleDelete, "rule", id, map[string]any{"name": gone.Name})
	}
	s.reloadEngine(r)
	w.WriteHeader(http.StatusNoContent)
}

// applyRule runs a rule against historical entries — the retroactive power
// of virtual buckets.
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
	res, err := s.store.ApplyRuleHistorical(r.Context(), *rule)
	if err != nil {
		s.internalError(w, "apply rule", err)
		return
	}
	s.record(r, audit.RuleApply, "rule", id,
		map[string]any{"name": rule.Name, "matched": res.Matched, "affected": res.Affected})
	writeJSON(w, res)
}

// ruleRefsExist rejects a rule whose tag or notify actions point at a tag or
// channel that doesn't exist (400), so a typo or a stale UI can't create a
// rule that fails every matching insert.
func (s *server) ruleRefsExist(w http.ResponseWriter, r *http.Request, rule store.Rule) bool {
	var tags, channels []int64
	for _, a := range rule.Actions {
		switch a.Type {
		case "tag":
			tags = append(tags, a.TagID)
		case "notify":
			channels = append(channels, a.ChannelID)
		}
	}
	missingTags, missingChannels, err := s.store.MissingRuleRefs(r.Context(), tags, channels)
	if err != nil {
		s.internalError(w, "check rule references", err)
		return false
	}
	switch {
	case len(missingTags) > 0:
		http.Error(w, fmt.Sprintf("tag action refers to unknown tag id(s) %v", missingTags), http.StatusBadRequest)
		return false
	case len(missingChannels) > 0:
		http.Error(w, fmt.Sprintf("notify action refers to unknown channel id(s) %v", missingChannels), http.StatusBadRequest)
		return false
	}
	return true
}

// ruleSummary names a rule and its action types for the audit log; the full
// condition stays in the rule itself.
func ruleSummary(rule store.Rule) map[string]any {
	actions := make([]string, 0, len(rule.Actions))
	for _, a := range rule.Actions {
		actions = append(actions, a.Type)
	}
	return map[string]any{"name": rule.Name, "enabled": rule.Enabled, "actions": actions}
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
