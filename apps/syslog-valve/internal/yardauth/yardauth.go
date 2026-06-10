// Package yardauth guards a yard tool's UI/API with the user accounts
// defined in syslog-bucket — the suite's identity provider. The tool never
// sees passwords or stores users: login is proxied to the bucket, and every
// request's bucket_session cookie is verified against the bucket's
// /api/auth/me (cached briefly). Because browser cookies are host-scoped
// (ports don't matter), signing in to any yard UI signs you into all of
// them on a standard same-host deployment.
//
// Unset YARD_AUTH_URL = guard disabled = the tool runs open (standalone
// mode, pre-S6 behavior). This file is identical in syslog-hose and
// syslog-valve; keep edits in sync.
package yardauth

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	cookieName = "bucket_session" // same cookie the bucket issues
	cacheTTL   = 30 * time.Second // verification cache; bounds revocation lag
)

// User is the subset of the bucket's user object the guard cares about.
type User struct {
	ID          int64  `json:"id"`
	Username    string `json:"username"`
	DisplayName string `json:"display_name"`
	Role        string `json:"role"`
}

type cacheEntry struct {
	user    User
	expires time.Time
}

type Guard struct {
	authURL      string // bucket base URL, e.g. http://syslog-bucket:8080
	cookieSecure bool
	client       *http.Client

	mu    sync.Mutex
	cache map[string]cacheEntry
}

// New returns a guard talking to the bucket at authURL; an empty authURL
// yields a disabled guard whose middleware passes everything through.
func New(authURL string, cookieSecure bool) *Guard {
	return &Guard{
		authURL:      strings.TrimRight(authURL, "/"),
		cookieSecure: cookieSecure,
		client:       &http.Client{Timeout: 5 * time.Second},
		cache:        map[string]cacheEntry{},
	}
}

func (g *Guard) Enabled() bool { return g.authURL != "" }

// Routes mounts the tool-local auth endpoints. They exist even when the
// guard is disabled so the SPA can always ask /api/auth/info.
func (g *Guard) Routes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/auth/info", g.handleInfo)
	mux.HandleFunc("GET /api/auth/me", g.handleMe)
	mux.HandleFunc("POST /api/auth/login", g.handleLogin)
	mux.HandleFunc("POST /api/auth/logout", g.handleLogout)
}

// public lists /api/ paths reachable without a session: liveness, the yard
// nav hints, and the auth endpoints themselves (which self-verify).
var public = map[string]bool{
	"/api/healthz":     true,
	"/api/hints":       true,
	"/api/auth/info":   true,
	"/api/auth/me":     true,
	"/api/auth/login":  true,
	"/api/auth/logout": true,
}

// Middleware rejects anonymous /api/ access and enforces the viewer role's
// read-only contract. Static SPA files stay open — the SPA renders the
// login screen itself.
func (g *Guard) Middleware(next http.Handler) http.Handler {
	if !g.Enabled() {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		if !strings.HasPrefix(p, "/api/") || public[p] {
			next.ServeHTTP(w, r)
			return
		}
		u, code := g.currentUser(r)
		if u == nil {
			http.Error(w, statusMessage(code), code)
			return
		}
		if u.Role == "viewer" && r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "read-only role", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func statusMessage(code int) string {
	if code == http.StatusServiceUnavailable {
		return "auth service (syslog-bucket) unreachable"
	}
	return "authentication required"
}

// currentUser resolves the request's session cookie, answering the HTTP
// status to use when there is no user (401 or 503).
func (g *Guard) currentUser(r *http.Request) (*User, int) {
	c, err := r.Cookie(cookieName)
	if err != nil || c.Value == "" {
		return nil, http.StatusUnauthorized
	}
	u, err := g.verify(r.Context(), c.Value)
	if err != nil {
		return nil, http.StatusServiceUnavailable
	}
	if u == nil {
		return nil, http.StatusUnauthorized
	}
	return u, http.StatusOK
}

// verify asks the bucket who the token belongs to, with a short positive
// cache so live tails and busy UIs don't hammer the bucket.
func (g *Guard) verify(ctx context.Context, token string) (*User, error) {
	now := time.Now()
	g.mu.Lock()
	if e, ok := g.cache[token]; ok && now.Before(e.expires) {
		u := e.user
		g.mu.Unlock()
		return &u, nil
	}
	g.mu.Unlock()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, g.authURL+"/api/auth/me", nil)
	if err != nil {
		return nil, err
	}
	req.AddCookie(&http.Cookie{Name: cookieName, Value: token})
	resp, err := g.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusUnauthorized:
		return nil, nil
	default:
		return nil, errors.New("auth service answered " + resp.Status)
	}
	var u User
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&u); err != nil {
		return nil, err
	}

	g.mu.Lock()
	for k, e := range g.cache { // drop stale entries while we're here
		if now.After(e.expires) {
			delete(g.cache, k)
		}
	}
	g.cache[token] = cacheEntry{user: u, expires: now.Add(cacheTTL)}
	g.mu.Unlock()
	return &u, nil
}

// --- handlers ---

func (g *Guard) handleInfo(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, map[string]bool{"enabled": g.Enabled()})
}

func (g *Guard) handleMe(w http.ResponseWriter, r *http.Request) {
	if !g.Enabled() {
		http.Error(w, "authentication disabled", http.StatusNotFound)
		return
	}
	u, code := g.currentUser(r)
	if u == nil {
		http.Error(w, statusMessage(code), code)
		return
	}
	writeJSON(w, u)
}

// handleLogin forwards the credentials to the bucket and, on success,
// re-issues the bucket's session token as this tool's own cookie.
func (g *Guard) handleLogin(w http.ResponseWriter, r *http.Request) {
	if !g.Enabled() {
		http.Error(w, "authentication disabled", http.StatusNotFound)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<16))
	if err != nil {
		http.Error(w, "invalid body", http.StatusBadRequest)
		return
	}
	req, err := http.NewRequestWithContext(r.Context(), http.MethodPost,
		g.authURL+"/api/auth/login", strings.NewReader(string(body)))
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := g.client.Do(req)
	if err != nil {
		http.Error(w, statusMessage(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<10))
		http.Error(w, strings.TrimSpace(string(msg)), resp.StatusCode)
		return
	}
	var token string
	maxAge := 0
	for _, c := range resp.Cookies() {
		if c.Name == cookieName {
			token, maxAge = c.Value, c.MaxAge
		}
	}
	if token == "" {
		http.Error(w, "auth service returned no session", http.StatusBadGateway)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: cookieName, Value: token, Path: "/",
		MaxAge: maxAge, HttpOnly: true,
		SameSite: http.SameSiteLaxMode, Secure: g.cookieSecure,
	})
	w.Header().Set("Content-Type", "application/json")
	io.Copy(w, io.LimitReader(resp.Body, 1<<16))
}

// handleLogout revokes the session at the bucket (signing the user out of
// every yard tool, since they share it) and clears the local cookie.
func (g *Guard) handleLogout(w http.ResponseWriter, r *http.Request) {
	if !g.Enabled() {
		http.Error(w, "authentication disabled", http.StatusNotFound)
		return
	}
	if c, err := r.Cookie(cookieName); err == nil && c.Value != "" {
		g.mu.Lock()
		delete(g.cache, c.Value)
		g.mu.Unlock()
		req, err := http.NewRequestWithContext(r.Context(), http.MethodPost,
			g.authURL+"/api/auth/logout", nil)
		if err == nil {
			req.AddCookie(&http.Cookie{Name: cookieName, Value: c.Value})
			if resp, err := g.client.Do(req); err == nil {
				resp.Body.Close()
			}
		}
	}
	http.SetCookie(w, &http.Cookie{
		Name: cookieName, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, SameSite: http.SameSiteLaxMode, Secure: g.cookieSecure,
	})
	w.WriteHeader(http.StatusNoContent)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}
