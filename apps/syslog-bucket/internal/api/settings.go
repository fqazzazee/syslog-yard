package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/syslog-yard/syslog-bucket/internal/auth"
	"github.com/syslog-yard/syslog-bucket/internal/store"
)

// Runtime settings that used to be env-only. A stored row wins over the env
// fallback (BUCKET_OIDC_* / the built-in default), and saving one hot-swaps the
// live auth service so no restart is needed.

// defaultIdleMinutes mirrors auth.defaultIdleTTL (30 days) so an unconfigured
// deployment behaves as before.
const defaultIdleMinutes = 30 * 24 * 60

type oidcSettings struct {
	Enabled      bool   `json:"enabled"`
	Issuer       string `json:"issuer"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret,omitempty"`
	RedirectURL  string `json:"redirect_url"`
	Name         string `json:"name"`
	DefaultRole  string `json:"default_role"`
}

type sessionSettings struct {
	IdleMinutes int `json:"idle_minutes"`
}

// envOIDC is the legacy environment-variable config (enabled when an issuer is
// set), used only when no DB row exists.
func (s *server) envOIDC() oidcSettings {
	return oidcSettings{
		Enabled:      s.cfg.OIDCIssuer != "",
		Issuer:       s.cfg.OIDCIssuer,
		ClientID:     s.cfg.OIDCClientID,
		ClientSecret: s.cfg.OIDCClientSecret,
		RedirectURL:  s.cfg.OIDCRedirectURL,
		Name:         s.cfg.OIDCName,
		DefaultRole:  s.cfg.OIDCDefaultRole,
	}
}

// resolveOIDC returns the effective OIDC settings and their source: a stored
// row ("db") wins; otherwise env ("env") if an issuer is set; otherwise "none".
func (s *server) resolveOIDC(ctx context.Context) (oidcSettings, string) {
	if raw, ok, _ := s.store.GetSetting(ctx, "oidc"); ok {
		var c oidcSettings
		if json.Unmarshal(raw, &c) == nil {
			return c, "db"
		}
	}
	if env := s.envOIDC(); env.Enabled {
		return env, "env"
	}
	return oidcSettings{Name: "SSO", DefaultRole: store.RoleAnalyst}, "none"
}

func (s *server) resolveIdleMinutes(ctx context.Context) int {
	if raw, ok, _ := s.store.GetSetting(ctx, "session"); ok {
		var ss sessionSettings
		if json.Unmarshal(raw, &ss) == nil && ss.IdleMinutes > 0 {
			return ss.IdleMinutes
		}
	}
	return defaultIdleMinutes
}

// buildOIDC turns settings into a live *auth.OIDC, or nil when SSO is off.
func buildOIDC(c oidcSettings) *auth.OIDC {
	if !c.Enabled || strings.TrimSpace(c.Issuer) == "" {
		return nil
	}
	name := c.Name
	if name == "" {
		name = "SSO"
	}
	role := c.DefaultRole
	if !store.ValidRole(role) {
		role = store.RoleAnalyst
	}
	return &auth.OIDC{
		Issuer: c.Issuer, ClientID: c.ClientID, ClientSecret: c.ClientSecret,
		RedirectURL: c.RedirectURL, Name: name, DefaultRole: role,
	}
}

// applyStoredSettings pushes the effective OIDC + idle config into the auth
// service. Called once at startup and after every settings change.
func (s *server) applyStoredSettings(ctx context.Context) {
	oc, _ := s.resolveOIDC(ctx)
	s.authSvc.SetOIDC(buildOIDC(oc))
	s.authSvc.SetIdleTTL(time.Duration(s.resolveIdleMinutes(ctx)) * time.Minute)
}

func (s *server) getSettings(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	oc, source := s.resolveOIDC(r.Context())
	writeJSON(w, map[string]any{
		"oidc": map[string]any{
			"enabled":      oc.Enabled,
			"issuer":       oc.Issuer,
			"client_id":    oc.ClientID,
			"redirect_url": oc.RedirectURL,
			"name":         oc.Name,
			"default_role": oc.DefaultRole,
			"has_secret":   oc.ClientSecret != "", // secret itself is never returned
			"source":       source,
		},
		"session": map[string]any{"idle_minutes": s.resolveIdleMinutes(r.Context())},
	})
}

func (s *server) putOIDCSettings(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	var in oidcSettings
	if !decodeJSON(w, r, &in) {
		return
	}
	if in.Enabled && strings.TrimSpace(in.Issuer) == "" {
		http.Error(w, "issuer is required to enable OIDC", http.StatusBadRequest)
		return
	}
	if in.DefaultRole != "" && !store.ValidRole(in.DefaultRole) {
		http.Error(w, "default_role must be admin, analyst, or viewer", http.StatusBadRequest)
		return
	}
	// A blank secret means "keep the one already stored", so a save from the UI
	// (which never receives the secret) doesn't wipe it.
	if in.ClientSecret == "" {
		if prev, _ := s.resolveOIDC(r.Context()); prev.ClientSecret != "" {
			in.ClientSecret = prev.ClientSecret
		}
	}
	if in.Name == "" {
		in.Name = "SSO"
	}
	if in.DefaultRole == "" {
		in.DefaultRole = store.RoleAnalyst
	}
	if err := s.store.PutSetting(r.Context(), "oidc", in); err != nil {
		s.internalError(w, "save oidc settings", err)
		return
	}
	o := buildOIDC(in)
	s.authSvc.SetOIDC(o)
	// Discovery probe gives immediate feedback without blocking the save.
	warning := ""
	if o != nil {
		if err := o.Probe(r.Context()); err != nil {
			warning = "Saved, but the issuer isn't reachable yet: " + err.Error()
		}
	}
	writeJSON(w, map[string]any{"ok": true, "warning": warning})
}

func (s *server) putSessionSettings(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	var in sessionSettings
	if !decodeJSON(w, r, &in) {
		return
	}
	if in.IdleMinutes < 1 || in.IdleMinutes > 525600 { // up to one year
		http.Error(w, "idle_minutes must be between 1 and 525600", http.StatusBadRequest)
		return
	}
	if err := s.store.PutSetting(r.Context(), "session", in); err != nil {
		s.internalError(w, "save session settings", err)
		return
	}
	s.authSvc.SetIdleTTL(time.Duration(in.IdleMinutes) * time.Minute)
	writeJSON(w, map[string]bool{"ok": true})
}
