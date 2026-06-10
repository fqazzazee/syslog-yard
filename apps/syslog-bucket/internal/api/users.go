package api

import (
	"net/http"
	"strings"

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
		if len(*req.Password) < 8 {
			http.Error(w, "password must be at least 8 characters", http.StatusBadRequest)
			return
		}
		hash, err := auth.HashPassword(*req.Password)
		if err != nil {
			s.internalError(w, "hash password", err)
			return
		}
		if _, err := s.store.SetPassword(r.Context(), id, hash); err != nil {
			s.internalError(w, "set password", err)
			return
		}
	}
	// Role changes, disables, and password resets all invalidate sessions.
	if req.Disabled || req.Password != nil {
		s.store.DeleteUserSessions(r.Context(), id)
	}
	user, err := s.store.GetUser(r.Context(), id)
	if err != nil || user == nil {
		s.internalError(w, "get user after update", err)
		return
	}
	writeJSON(w, user)
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
	if err := s.store.DeleteUser(r.Context(), id); err != nil {
		s.internalError(w, "delete user", err)
		return
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
	shares, err := s.store.ListBucketShares(r.Context(), b.ID)
	if err != nil {
		s.internalError(w, "list bucket shares", err)
		return
	}
	writeJSON(w, map[string]any{"shares": shares})
}
