// Package yardauth guards a yard tool's UI/API with the user accounts
// defined in syslog-bucket — the suite's identity provider. The tool never
// sees passwords or stores users: login is proxied to the bucket, and every
// request's bucket_session cookie is verified against the bucket's
// /api/auth/me (cached briefly). Because browser cookies are host-scoped
// (ports don't matter), signing in to any yard UI signs you into all of
// them on a standard same-host deployment.
//
// Unset YARD_AUTH_URL = guard disabled = the tool runs open (standalone
// mode). Shared by syslog-hose and syslog-valve; the bucket is the identity
// provider itself and has its own internal/auth.
package yardauth

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/syslog-yard/shared/secure"
)

const (
	cookieName = "bucket_session" // same cookie the bucket issues
	cacheTTL   = 30 * time.Second // verification cache; bounds revocation lag
	// sessionRecheck is how often an open stream re-verifies its session.
	sessionRecheck = 30 * time.Second
)

// User is the subset of the bucket's user object the guard cares about.
// HasPassword distinguishes local accounts from OIDC-only ones (the
// account dialog offers password change only for the former).
type User struct {
	ID          int64  `json:"id"`
	Username    string `json:"username"`
	DisplayName string `json:"display_name"`
	Role        string `json:"role"`
	HasPassword bool   `json:"has_password"`
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
	// slid holds, per token, the new cookie expiry the bucket reported and
	// the browser hasn't been told yet. The bucket refreshes at most once a
	// minute, and that answer may land on a cached path, so it waits for the
	// next request.
	slid map[string]time.Time

	recheck time.Duration // see SetSessionRecheck

	anonymous map[string]bool // tool-specific additions to public
}

// session is what Middleware leaves in the request context.
type session struct {
	guard *Guard
	token string
	user  User
}

type sessionKey struct{}

// UserFrom returns the user Middleware verified for this request, or nil
// (guard disabled, or a public path).
func UserFrom(ctx context.Context) *User {
	if s, ok := ctx.Value(sessionKey{}).(*session); ok {
		u := s.user
		return &u
	}
	return nil
}

// WatchSession returns a context for a long-lived response: it is cancelled
// when the request ends or the bucket definitely rejects the session (401).
// Anything else, such as a bucket outage, keeps the stream open and is
// retried at the next recheck. Rechecks don't count as activity, so an open
// stream can't hold off the idle timeout. Call the returned function when done.
func WatchSession(r *http.Request) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(r.Context())
	s, ok := r.Context().Value(sessionKey{}).(*session)
	if !ok {
		return ctx, cancel
	}
	go func() {
		tick := time.NewTicker(s.guard.recheck)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
			}
			if live, err := s.guard.sessionLive(ctx, s.token); err == nil && !live {
				cancel()
				return
			}
		}
	}()
	return ctx, cancel
}

// SetSessionRecheck changes how often WatchSession re-verifies a session.
// Call it before the handler serves; tests use it to avoid waiting.
func (g *Guard) SetSessionRecheck(d time.Duration) { g.recheck = d }

// New returns a guard talking to the bucket at authURL; an empty authURL
// yields a disabled guard whose middleware passes everything through.
func New(authURL string, cookieSecure bool) *Guard {
	return &Guard{
		authURL:      strings.TrimRight(authURL, "/"),
		cookieSecure: cookieSecure,
		client:       &http.Client{Timeout: 5 * time.Second},
		cache:        map[string]cacheEntry{},
		slid:         map[string]time.Time{},
		recheck:      sessionRecheck,
	}
}

func (g *Guard) Enabled() bool { return g.authURL != "" }

// AllowAnonymous makes exact /api/ paths reachable without a session, on
// top of the suite-wide public list. Only for data that is public anyway
// (e.g. a TLS certificate every client sees in the handshake). Call it
// before the handler serves.
func (g *Guard) AllowAnonymous(paths ...string) {
	if g.anonymous == nil {
		g.anonymous = map[string]bool{}
	}
	for _, p := range paths {
		g.anonymous[p] = true
	}
}

// Routes mounts the tool-local auth endpoints. They exist even when the
// guard is disabled so the SPA can always ask /api/auth/info. Account
// management (password change, user admin) is proxied to the bucket so
// every yard UI offers the same account menu; the bucket enforces roles.
func (g *Guard) Routes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/auth/info", g.handleInfo)
	mux.HandleFunc("GET /api/auth/me", g.handleMe)
	mux.HandleFunc("POST /api/auth/login", g.handleLogin)
	mux.HandleFunc("POST /api/auth/logout", g.handleLogout)
	mux.HandleFunc("PUT /api/auth/password", g.proxyTo("/api/auth/password"))
	mux.HandleFunc("GET /api/users", g.proxyTo("/api/users"))
	mux.HandleFunc("POST /api/users", g.proxyTo("/api/users"))
	mux.HandleFunc("PUT /api/users/{id}", g.proxyUser)
	mux.HandleFunc("DELETE /api/users/{id}", g.proxyUser)
}

// proxyTo forwards to one fixed bucket path. The upstream URL is never
// derived from the (decoded) request path, so an encoded "../" in it
// cannot steer the proxy to another bucket endpoint.
func (g *Guard) proxyTo(path string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) { g.proxy(w, r, path) }
}

// proxyUser forwards /api/users/{id}, accepting only a decimal id.
func (g *Guard) proxyUser(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		http.Error(w, "invalid user id", http.StatusBadRequest)
		return
	}
	g.proxy(w, r, "/api/users/"+strconv.FormatInt(id, 10))
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
		if !strings.HasPrefix(p, "/api/") || public[p] || g.anonymous[p] {
			next.ServeHTTP(w, r)
			return
		}
		u, code := g.currentUser(w, r)
		if u == nil {
			http.Error(w, statusMessage(code), code)
			return
		}
		// Viewers are read-only, except for changing their own password.
		if u.Role == "viewer" && r.Method != http.MethodGet && r.Method != http.MethodHead &&
			p != "/api/auth/password" {
			http.Error(w, "read-only role", http.StatusForbidden)
			return
		}
		c, err := r.Cookie(cookieName)
		if err != nil { // currentUser just read it
			http.Error(w, statusMessage(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
		ctx := context.WithValue(r.Context(), sessionKey{}, &session{guard: g, token: c.Value, user: *u})
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func statusMessage(code int) string {
	if code == http.StatusServiceUnavailable {
		return "auth service (syslog-bucket) unreachable"
	}
	return "authentication required"
}

// currentUser resolves the request's session cookie, answering the HTTP
// status to use when there is no user (401 or 503). A session expiry the
// bucket moved forward is passed on to the browser through w.
func (g *Guard) currentUser(w http.ResponseWriter, r *http.Request) (*User, int) {
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
	g.sendSlidCookie(w, c.Value)
	return u, http.StatusOK
}

// sendSlidCookie re-issues the session cookie if the bucket has moved its
// expiry since the browser last heard, with the time already elapsed taken
// off Max-Age.
func (g *Guard) sendSlidCookie(w http.ResponseWriter, token string) {
	g.mu.Lock()
	expires, ok := g.slid[token]
	delete(g.slid, token)
	g.mu.Unlock()
	if !ok {
		return
	}
	maxAge := int(time.Until(expires).Seconds())
	if maxAge <= 0 {
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: cookieName, Value: token, Path: "/",
		MaxAge: maxAge, HttpOnly: true,
		SameSite: http.SameSiteLaxMode, Secure: g.cookieSecure,
	})
}

// verify asks the bucket who the token belongs to, with a short positive
// cache so live tails and busy UIs don't hammer the bucket.
func (g *Guard) verify(ctx context.Context, token string) (*User, error) {
	g.mu.Lock()
	if e, ok := g.cache[token]; ok && time.Now().Before(e.expires) {
		u := e.user
		g.mu.Unlock()
		return &u, nil
	}
	g.mu.Unlock()
	return g.fetch(ctx, token)
}

// fetch asks the bucket directly, refreshing the cache. It answers (nil,
// nil) only for a definite 401; every other failure is an error.
func (g *Guard) fetch(ctx context.Context, token string) (*User, error) {
	now := time.Now()
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
		g.mu.Lock()
		delete(g.cache, token)
		delete(g.slid, token)
		g.mu.Unlock()
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
	for k, expires := range g.slid {
		if now.After(expires) {
			delete(g.slid, k)
		}
	}
	g.cache[token] = cacheEntry{user: u, expires: now.Add(cacheTTL)}
	for _, c := range resp.Cookies() {
		if c.Name == cookieName && c.Value == token && c.MaxAge > 0 {
			g.slid[token] = now.Add(time.Duration(c.MaxAge) * time.Second)
		}
	}
	g.mu.Unlock()
	return &u, nil
}

// sessionLive asks the bucket whether token is still a live session, without
// counting as activity: the expiry doesn't move and no cookie comes back. It
// answers false only for a definite 401; every other failure is an error.
func (g *Guard) sessionLive(ctx context.Context, token string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, g.authURL+"/api/auth/session", nil)
	if err != nil {
		return false, err
	}
	req.AddCookie(&http.Cookie{Name: cookieName, Value: token})
	resp, err := g.client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusNoContent:
		return true, nil
	case http.StatusUnauthorized:
		g.mu.Lock()
		delete(g.cache, token)
		delete(g.slid, token)
		g.mu.Unlock()
		return false, nil
	}
	return false, errors.New("auth service answered " + resp.Status)
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
	u, code := g.currentUser(w, r)
	if u == nil {
		http.Error(w, statusMessage(code), code)
		return
	}
	writeJSON(w, u)
}

// handleLogin forwards the credentials to the bucket and, on success,
// re-issues the bucket's session token as this tool's own cookie. The
// client's address (secure.ClientIP) travels as X-Forwarded-For so the
// bucket's per-(username, IP) login throttle sees the real client rather
// than this tool; the bucket must believe that header only from peers it
// is configured to trust as proxies (the yard tools).
func (g *Guard) handleLogin(w http.ResponseWriter, r *http.Request) {
	if !g.Enabled() {
		http.Error(w, "authentication disabled", http.StatusNotFound)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<16))
	if err != nil {
		secure.WriteBodyError(w, err)
		return
	}
	req, err := http.NewRequestWithContext(r.Context(), http.MethodPost,
		g.authURL+"/api/auth/login", strings.NewReader(string(body)))
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Forwarded-For", secure.ClientIP(r))
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
		delete(g.slid, c.Value)
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

// proxy forwards an account-management request to the bucket path given
// (method, body, session cookie, client IP) and relays the answer. A
// re-issued session cookie — the bucket rotates it on password change — is
// passed along so the user stays signed in.
func (g *Guard) proxy(w http.ResponseWriter, r *http.Request, path string) {
	if !g.Enabled() {
		http.Error(w, "authentication disabled", http.StatusNotFound)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
	if err != nil {
		secure.WriteBodyError(w, err)
		return
	}
	req, err := http.NewRequestWithContext(r.Context(), r.Method,
		g.authURL+path, strings.NewReader(string(body)))
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Forwarded-For", secure.ClientIP(r))
	var oldToken string
	if c, err := r.Cookie(cookieName); err == nil {
		oldToken = c.Value
		req.AddCookie(&http.Cookie{Name: cookieName, Value: c.Value})
	}
	resp, err := g.client.Do(req)
	if err != nil {
		http.Error(w, statusMessage(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		return
	}
	defer resp.Body.Close()
	for _, c := range resp.Cookies() {
		if c.Name == cookieName && c.Value != "" {
			g.mu.Lock()
			delete(g.cache, oldToken) // the old session was just revoked
			delete(g.slid, oldToken)
			g.mu.Unlock()
			http.SetCookie(w, &http.Cookie{
				Name: cookieName, Value: c.Value, Path: "/",
				MaxAge: c.MaxAge, HttpOnly: true,
				SameSite: http.SameSiteLaxMode, Secure: g.cookieSecure,
			})
		}
	}
	if ct := resp.Header.Get("Content-Type"); ct != "" {
		w.Header().Set("Content-Type", ct)
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, io.LimitReader(resp.Body, 1<<20))
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}
