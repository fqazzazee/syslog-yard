package api

import (
	"net/http"
	"strings"

	"github.com/syslog-yard/syslog-bucket/internal/audit"
	"github.com/syslog-yard/syslog-bucket/internal/auth"
	"github.com/syslog-yard/syslog-bucket/internal/store"
)

// User management is admin-only except for listing, which every signed-in
// user needs to populate the bucket-share picker.

func (s *server) listUsers(w http.ResponseWriter, r *http.Request) {
	users, err := s.store.ListUsers(r.Context())
	if err != nil {
		s.internalError(w, "list users", err)
		return
	}
	writeJSON(w, map[string]any{"users": users})
}

func (s *server) requireAdmin(w http.ResponseWriter, r *http.Request) bool {
	if auth.UserFrom(r.Context()).Role != store.RoleAdmin {
		http.Error(w, "admin role required", http.StatusForbidden)
		return false
	}
	return true
}

func (s *server) createUser(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	var req struct {
		Username    string `json:"username"`
		DisplayName string `json:"display_name"`
		Email       string `json:"email"`
		Role        string `json:"role"`
		Password    string `json:"password"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	req.Username = strings.TrimSpace(req.Username)
	if req.Username == "" || !store.ValidRole(req.Role) {
		http.Error(w, "username and a valid role (admin/analyst/viewer) required", http.StatusBadRequest)
		return
	}
	if len(req.Password) < 8 {
		http.Error(w, "password must be at least 8 characters", http.StatusBadRequest)
		return
	}
	hash, err := auth.HashPassword(req.Password)
	if err != nil {
		s.internalError(w, "hash password", err)
		return
	}
	created, err := s.store.CreateUser(r.Context(), store.User{
		Username: req.Username, DisplayName: req.DisplayName, Email: req.Email,
		Role: req.Role, PasswordHash: hash,
	}, "")
	if err != nil {
		s.writeError(w, "create user", err)
		return
	}
	s.record(r, audit.UserCreate, "user", created.ID, map[string]any{"username": created.Username, "role": created.Role})
	writeJSON(w, created)
}

func (s *server) updateUser(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	var req struct {
		DisplayName string  `json:"display_name"`
		Email       string  `json:"email"`
		Role        string  `json:"role"`
		Disabled    bool    `json:"disabled"`
		Password    *string `json:"password"` // set = reset it
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	if !store.ValidRole(req.Role) {
		http.Error(w, "role must be admin, analyst, or viewer", http.StatusBadRequest)
		return
	}
	me := auth.UserFrom(r.Context())
	if id == me.ID && (req.Role != store.RoleAdmin || req.Disabled) {
		http.Error(w, "you cannot demote or disable your own account", http.StatusBadRequest)
		return
	}
	// Validate everything before writing anything, so a bad password can't
	// leave a half-applied update behind.
	var hash string
	if req.Password != nil {
		if len(*req.Password) < 8 {
			http.Error(w, "password must be at least 8 characters", http.StatusBadRequest)
			return
		}
		var err error
		if hash, err = auth.HashPassword(*req.Password); err != nil {
			s.internalError(w, "hash password", err)
			return
		}
	}
	before, err := s.store.GetUser(r.Context(), id)
	if err != nil {
		s.internalError(w, "get user", err)
		return
	}
	if before == nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	found, err := s.store.UpdateUser(r.Context(), id, req.DisplayName, req.Email, req.Role, req.Disabled)
	if err != nil {
		s.internalError(w, "update user", err)
		return
	}
	if !found {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if req.Password != nil {
		if _, err := s.store.SetPassword(r.Context(), id, hash); err != nil {
			s.internalError(w, "set password", err)
			return
		}
	}
	// Disables, demotions, and password resets revoke the user's sessions.
	// The middleware re-reads the role on every request, so this matters less
	// for the bucket's REST API than for the hose and valve (which cache a
	// session's user for up to 30 s) and for open live tails (which re-check
	// their session every 30 s). Promotions keep the sessions.
	revoked := sessionsRevokedBy(before, req.Role, req.Disabled, req.Password != nil)
	if revoked {
		if err := s.store.DeleteUserSessions(r.Context(), id); err != nil {
			s.internalError(w, "revoke sessions", err)
			return
		}
	}
	s.recordUserUpdate(r, before, req.DisplayName, req.Email, req.Role, req.Disabled, req.Password != nil, revoked)
	user, err := s.store.GetUser(r.Context(), id)
	if err != nil || user == nil {
		s.internalError(w, "get user after update", err)
		return
	}
	writeJSON(w, user)
}

// recordUserUpdate audits an admin edit of an account: the fields that
// changed (one user.update event) and, separately, a password reset (whose
// value is never recorded).
func (s *server) recordUserUpdate(r *http.Request, before *store.User, displayName, email, role string, disabled, passwordReset, revoked bool) {
	changes := map[string]any{}
	if role != before.Role {
		changes["role"] = change(before.Role, role)
	}
	if disabled != before.Disabled {
		changes["disabled"] = change(before.Disabled, disabled)
	}
	if displayName != before.DisplayName {
		changes["display_name"] = change(before.DisplayName, displayName)
	}
	if email != before.Email {
		changes["email"] = change(before.Email, email)
	}
	if len(changes) > 0 {
		changes["username"] = before.Username
		if revoked && !passwordReset {
			changes["sessions_revoked"] = true
		}
		s.record(r, audit.UserUpdate, "user", before.ID, changes)
	}
	if passwordReset {
		s.record(r, audit.UserPasswordReset, "user", before.ID,
			map[string]any{"username": before.Username, "sessions_revoked": true})
	}
}

// roleRank orders roles by privilege so demotions can be detected.
func roleRank(role string) int {
	switch role {
	case store.RoleAdmin:
		return 3
	case store.RoleAnalyst:
		return 2
	case store.RoleViewer:
		return 1
	}
	return 0
}

// sessionsRevokedBy reports whether an admin edit of user before must log
// them out everywhere: disabling, lowering the role, or resetting the
// password.
func sessionsRevokedBy(before *store.User, newRole string, disabled, passwordReset bool) bool {
	return disabled || passwordReset || roleRank(newRole) < roleRank(before.Role)
}

func (s *server) deleteUser(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	if id == auth.UserFrom(r.Context()).ID {
		http.Error(w, "you cannot delete your own account", http.StatusBadRequest)
		return
	}
	// Snapshot the account for the audit row before it goes.
	gone, err := s.store.GetUser(r.Context(), id)
	if err != nil {
		s.internalError(w, "get user", err)
		return
	}
	if err := s.store.DeleteUser(r.Context(), id); err != nil {
		s.internalError(w, "delete user", err)
		return
	}
	if gone != nil {
		s.record(r, audit.UserDelete, "user", id, map[string]any{"username": gone.Username, "role": gone.Role})
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- bucket shares ---

func (s *server) listBucketShares(w http.ResponseWriter, r *http.Request) {
	b := s.visibleBucket(w, r)
	if b == nil {
		return
	}
	if !canManageBucket(auth.UserFrom(r.Context()), b) {
		http.Error(w, "only the owner or an admin can view sharing", http.StatusForbidden)
		return
	}
	shares, err := s.store.ListBucketShares(r.Context(), b.ID)
	if err != nil {
		s.internalError(w, "list bucket shares", err)
		return
	}
	writeJSON(w, map[string]any{"shares": shares})
}

func (s *server) putBucketShares(w http.ResponseWriter, r *http.Request) {
	b := s.visibleBucket(w, r)
	if b == nil {
		return
	}
	if !canManageBucket(auth.UserFrom(r.Context()), b) {
		http.Error(w, "only the owner or an admin can change sharing", http.StatusForbidden)
		return
	}
	var req struct {
		Shares []store.BucketShare `json:"shares"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	if err := s.store.ReplaceBucketShares(r.Context(), b.ID, req.Shares); err != nil {
		s.internalError(w, "replace bucket shares", err)
		return
	}
	shared := make([]map[string]any, 0, len(req.Shares))
	for _, sh := range req.Shares {
		shared = append(shared, map[string]any{"user_id": sh.UserID, "can_edit": sh.CanEdit})
	}
	s.record(r, audit.BucketShare, "bucket", b.ID, map[string]any{"name": b.Name, "shares": shared})
	shares, err := s.store.ListBucketShares(r.Context(), b.ID)
	if err != nil {
		s.internalError(w, "list bucket shares", err)
		return
	}
	writeJSON(w, map[string]any{"shares": shares})
}
