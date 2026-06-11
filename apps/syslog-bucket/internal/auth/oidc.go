package auth

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/syslog-yard/syslog-bucket/internal/store"
)

const stateCookie = "bucket_oidc_state"

// OIDC describes one configured identity provider (Keycloak, Authentik,
// Entra ID, Google, …). The provider's discovery document is fetched
// lazily and cached, so the bucket can start before the IdP is reachable.
type OIDC struct {
	Issuer       string
	ClientID     string
	ClientSecret string
	RedirectURL  string
	Name         string // login-button label
	DefaultRole  string // role for auto-provisioned users

	mu       sync.Mutex
	provider *oidc.Provider
}

func (o *OIDC) discover(ctx context.Context) (*oidc.Provider, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.provider == nil {
		p, err := oidc.NewProvider(ctx, o.Issuer)
		if err != nil {
			return nil, fmt.Errorf("oidc discovery (%s): %w", o.Issuer, err)
		}
		o.provider = p
	}
	return o.provider, nil
}

func (o *OIDC) oauthConfig(p *oidc.Provider) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     o.ClientID,
		ClientSecret: o.ClientSecret,
		RedirectURL:  o.RedirectURL,
		Endpoint:     p.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
	}
}

// HandleOIDCLogin starts the code flow: random state in a short-lived
// cookie, then redirect to the provider.
func (s *Service) HandleOIDCLogin(w http.ResponseWriter, r *http.Request) {
	if s.oidc == nil {
		http.Error(w, "OIDC is not configured", http.StatusNotFound)
		return
	}
	p, err := s.oidc.discover(r.Context())
	if err != nil {
		http.Error(w, "identity provider unreachable: "+err.Error(), http.StatusBadGateway)
		return
	}
	state := randHex(16)
	http.SetCookie(w, &http.Cookie{
		Name: stateCookie, Value: state, Path: "/api/auth/oidc",
		MaxAge: int((10 * time.Minute).Seconds()), HttpOnly: true,
		SameSite: http.SameSiteLaxMode, Secure: s.cookieSecure,
	})
	http.Redirect(w, r, s.oidc.oauthConfig(p).AuthCodeURL(state), http.StatusFound)
}

// HandleOIDCCallback finishes the flow: verify state and ID token, map the
// subject to a user (auto-provisioning on first sign-in), issue a session.
func (s *Service) HandleOIDCCallback(w http.ResponseWriter, r *http.Request) {
	if s.oidc == nil {
		http.Error(w, "OIDC is not configured", http.StatusNotFound)
		return
	}
	c, err := r.Cookie(stateCookie)
	if err != nil || c.Value == "" || r.URL.Query().Get("state") != c.Value {
		http.Error(w, "OIDC state mismatch — restart sign-in", http.StatusBadRequest)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: stateCookie, Value: "", Path: "/api/auth/oidc", MaxAge: -1})

	p, err := s.oidc.discover(r.Context())
	if err != nil {
		http.Error(w, "identity provider unreachable: "+err.Error(), http.StatusBadGateway)
		return
	}
	token, err := s.oidc.oauthConfig(p).Exchange(r.Context(), r.URL.Query().Get("code"))
	if err != nil {
		http.Error(w, "OIDC code exchange failed: "+err.Error(), http.StatusBadGateway)
		return
	}
	rawID, ok := token.Extra("id_token").(string)
	if !ok {
		http.Error(w, "provider returned no id_token", http.StatusBadGateway)
		return
	}
	idToken, err := p.Verifier(&oidc.Config{ClientID: s.oidc.ClientID}).Verify(r.Context(), rawID)
	if err != nil {
		http.Error(w, "ID token verification failed: "+err.Error(), http.StatusBadGateway)
		return
	}
	var claims struct {
		PreferredUsername string `json:"preferred_username"`
		Email             string `json:"email"`
		Name              string `json:"name"`
	}
	if err := idToken.Claims(&claims); err != nil {
		http.Error(w, "unreadable ID token claims", http.StatusBadGateway)
		return
	}

	u, err := s.userForSubject(r.Context(), idToken.Subject, claims.PreferredUsername, claims.Email, claims.Name)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if u.Disabled {
		http.Error(w, "account is disabled", http.StatusForbidden)
		return
	}
	if err := s.issueSession(r.Context(), w, u.ID); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// userForSubject finds the account bound to an OIDC subject, creating one
// on first sign-in (OIDC subject mapping). Username collisions
// with existing local accounts get a subject-derived suffix rather than
// silently hijacking the local account.
func (s *Service) userForSubject(ctx context.Context, subject, preferred, email, name string) (*store.User, error) {
	if u, err := s.store.GetUserByOIDCSubject(ctx, subject); err != nil || u != nil {
		return u, err
	}
	username := strings.TrimSpace(preferred)
	if username == "" {
		username = strings.TrimSpace(email)
	}
	if username == "" {
		username = "oidc-" + subject
	}
	role := s.oidc.DefaultRole
	if !store.ValidRole(role) {
		role = store.RoleAnalyst
	}
	u := store.User{Username: username, DisplayName: name, Email: email, Role: role}
	created, err := s.store.CreateUser(ctx, u, subject)
	if err != nil && len(subject) >= 6 {
		u.Username = username + "-" + subject[:6]
		created, err = s.store.CreateUser(ctx, u, subject)
	}
	if err != nil {
		return nil, err
	}
	return &created, nil
}
