package auth

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/syslog-yard/syslog-bucket/internal/store"
)

const stateCookie = "bucket_oidc_state"

// DefaultOIDCRole is the role given to first-time SSO users when none is
// configured: read-only, so an IdP that admits more people than intended
// can't hand out write access. Admins promote users afterwards.
const DefaultOIDCRole = store.RoleViewer

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

// Probe forces discovery now so the settings UI can flag an unreachable issuer
// immediately, rather than only at the first sign-in attempt.
func (o *OIDC) Probe(ctx context.Context) error {
	_, err := o.discover(ctx)
	return err
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

// flowState is what the login step remembers for the callback, kept in a
// short-lived HttpOnly cookie scoped to /api/auth/oidc: the CSRF state, the
// ID-token nonce (binds the token to this browser's sign-in, defeating
// replay/injection), and the PKCE verifier (binds the authorization code to
// it, so an intercepted code is useless).
type flowState struct {
	State, Nonce, Verifier string
}

func (f flowState) encode() string { return f.State + "." + f.Nonce + "." + f.Verifier }

func decodeFlowState(v string) (flowState, bool) {
	parts := strings.Split(v, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return flowState{}, false
	}
	return flowState{State: parts[0], Nonce: parts[1], Verifier: parts[2]}, true
}

// oidcFailed answers a failed sign-in step. The callback page is public and
// reflects whatever the IdP or token endpoint said, so details only go to
// the log; the browser gets a generic message.
func oidcFailed(w http.ResponseWriter, status int, step string, err error) {
	slog.Warn("oidc sign-in failed", "step", step, "error", err)
	http.Error(w, "Single sign-on failed. Try again, or ask an administrator to check the server log.", status)
}

// HandleOIDCLogin starts the authorization-code flow with PKCE (S256) and a
// nonce: fresh state, nonce, and verifier go into a short-lived cookie, then
// the browser is redirected to the provider.
func (s *Service) HandleOIDCLogin(w http.ResponseWriter, r *http.Request) {
	o := s.currentOIDC()
	if o == nil {
		http.Error(w, "OIDC is not configured", http.StatusNotFound)
		return
	}
	p, err := o.discover(r.Context())
	if err != nil {
		oidcFailed(w, http.StatusBadGateway, "discovery", err)
		return
	}
	f := flowState{State: randHex(16), Nonce: randHex(16), Verifier: oauth2.GenerateVerifier()}
	http.SetCookie(w, &http.Cookie{
		Name: stateCookie, Value: f.encode(), Path: "/api/auth/oidc",
		MaxAge: int((10 * time.Minute).Seconds()), HttpOnly: true,
		SameSite: http.SameSiteLaxMode, Secure: s.cookieSecure,
	})
	url := o.oauthConfig(p).AuthCodeURL(f.State, oidc.Nonce(f.Nonce), oauth2.S256ChallengeOption(f.Verifier))
	http.Redirect(w, r, url, http.StatusFound)
}

// HandleOIDCCallback finishes the flow: verify state, redeem the code with
// the PKCE verifier, verify the ID token and its nonce, map the subject to a
// user (auto-provisioning on first sign-in), issue a session.
func (s *Service) HandleOIDCCallback(w http.ResponseWriter, r *http.Request) {
	o := s.currentOIDC()
	if o == nil {
		http.Error(w, "OIDC is not configured", http.StatusNotFound)
		return
	}
	q := r.URL.Query()
	var f flowState
	c, err := r.Cookie(stateCookie)
	if err == nil {
		f, _ = decodeFlowState(c.Value)
	}
	if f.State == "" || subtle.ConstantTimeCompare([]byte(q.Get("state")), []byte(f.State)) != 1 {
		http.Error(w, "OIDC state mismatch — restart sign-in", http.StatusBadRequest)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: stateCookie, Value: "", Path: "/api/auth/oidc", MaxAge: -1,
		HttpOnly: true, SameSite: http.SameSiteLaxMode, Secure: s.cookieSecure,
	})
	if e := q.Get("error"); e != "" {
		oidcFailed(w, http.StatusUnauthorized, "authorize",
			fmt.Errorf("provider returned %s: %s", e, q.Get("error_description")))
		return
	}

	id, step, err := o.redeem(r.Context(), q.Get("code"), f)
	if err != nil {
		oidcFailed(w, http.StatusBadGateway, step, err)
		return
	}

	u, err := s.userForSubject(r.Context(), o, id.Subject, id.PreferredUsername, id.Email, id.Name)
	if err != nil {
		slog.Error("oidc: provision user", "error", err)
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

// identity is what a verified ID token tells us about the user.
type identity struct {
	Subject           string `json:"sub"`
	PreferredUsername string `json:"preferred_username"`
	Email             string `json:"email"`
	Name              string `json:"name"`
}

// redeem trades an authorization code (plus the PKCE verifier) for tokens and
// verifies the ID token — signature, issuer, audience, expiry, and that its
// nonce is the one this browser's sign-in started with. On failure it names
// the step for the log.
func (o *OIDC) redeem(ctx context.Context, code string, f flowState) (identity, string, error) {
	p, err := o.discover(ctx)
	if err != nil {
		return identity{}, "discovery", err
	}
	token, err := o.oauthConfig(p).Exchange(ctx, code, oauth2.VerifierOption(f.Verifier))
	if err != nil {
		return identity{}, "code exchange", err
	}
	rawID, ok := token.Extra("id_token").(string)
	if !ok {
		return identity{}, "code exchange", errors.New("provider returned no id_token")
	}
	idToken, err := p.Verifier(&oidc.Config{ClientID: o.ClientID}).Verify(ctx, rawID)
	if err != nil {
		return identity{}, "id token", err
	}
	if subtle.ConstantTimeCompare([]byte(idToken.Nonce), []byte(f.Nonce)) != 1 {
		return identity{}, "id token", errors.New("nonce mismatch")
	}
	var id identity
	if err := idToken.Claims(&id); err != nil {
		return identity{}, "id token claims", err
	}
	id.Subject = idToken.Subject
	return id, "", nil
}

// userForSubject finds the account bound to an OIDC subject, creating one
// on first sign-in (OIDC subject mapping). Username collisions
// with existing local accounts get a subject-derived suffix rather than
// silently hijacking the local account.
func (s *Service) userForSubject(ctx context.Context, o *OIDC, subject, preferred, email, name string) (*store.User, error) {
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
	role := o.DefaultRole
	if !store.ValidRole(role) {
		role = DefaultOIDCRole
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
