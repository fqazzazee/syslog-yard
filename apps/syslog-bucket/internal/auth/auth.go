// Package auth implements authentication: local accounts
// with bcrypt passwords, optional OIDC, opaque cookie sessions stored
// hashed in Postgres, and the role middleware the API mounts in front of
// every handler.
package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"mime"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/syslog-yard/syslog-bucket/internal/store"
)

const (
	sessionCookie = "bucket_session"
	// defaultIdleTTL applies until an admin sets one; generous so existing
	// deployments aren't logged out before they configure it.
	defaultIdleTTL = 30 * 24 * time.Hour
	minPassword    = 8

	// Brute-force throttle (see guard): one source is locked out of an
	// account for loginWindow after loginMaxFails consecutive bad passwords;
	// the account itself locks for accountWindow once accountMaxFails pile up
	// from all sources within one accountWindow.
	loginMaxFails   = 10
	loginWindow     = 5 * time.Minute
	accountMaxFails = 100
	accountWindow   = 15 * time.Minute
)

type Service struct {
	store        *store.Store
	cookieSecure bool
	loginGuard   *guard // POST /api/auth/login, keyed by username
	pwGuard      *guard // PUT /api/auth/password, keyed by user id

	// oidc, idleTTL and trusted are runtime-configurable, so they're guarded
	// rather than fixed at construction.
	mu      sync.RWMutex
	oidc    *OIDC // nil = OIDC disabled
	idleTTL time.Duration
	trusted []netip.Prefix // proxies whose X-Forwarded-For is believed
}

func New(st *store.Store, cookieSecure bool) *Service {
	return &Service{
		store:        st,
		cookieSecure: cookieSecure,
		loginGuard:   newGuard(),
		pwGuard:      newGuard(),
		idleTTL:      defaultIdleTTL,
	}
}

// SetTrustedProxies sets the reverse proxies whose X-Forwarded-For header is
// used to find the client address for brute-force throttling. Empty (the
// default) means the TCP peer address is always used.
func (s *Service) SetTrustedProxies(p []netip.Prefix) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.trusted = p
}

func (s *Service) clientIP(r *http.Request) string {
	s.mu.RLock()
	trusted := s.trusted
	s.mu.RUnlock()
	return clientIP(r, trusted)
}

// SetOIDC swaps the live identity-provider config (nil disables SSO). The next
// sign-in and the login page's /api/auth/info pick it up immediately.
func (s *Service) SetOIDC(o *OIDC) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.oidc = o
}

// SetIdleTTL sets how long a session survives without activity. Applies to
// sessions issued or slid after the change.
func (s *Service) SetIdleTTL(d time.Duration) {
	if d <= 0 {
		d = defaultIdleTTL
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.idleTTL = d
}

func (s *Service) currentOIDC() *OIDC {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.oidc
}

func (s *Service) currentIdle() time.Duration {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.idleTTL
}

// Bootstrap creates the initial admin account on an empty users table.
// Without BUCKET_ADMIN_PASSWORD a random password is generated and printed
// to the log once — change it from the UI afterwards.
func Bootstrap(ctx context.Context, st *store.Store, adminPassword string) error {
	n, err := st.CountUsers(ctx)
	if err != nil || n > 0 {
		return err
	}
	generated := adminPassword == ""
	if generated {
		adminPassword = generatePassword()
	}
	hash, err := HashPassword(adminPassword)
	if err != nil {
		return err
	}
	if _, err := st.CreateUser(ctx, store.User{
		Username: "admin", DisplayName: "Administrator", Role: store.RoleAdmin, PasswordHash: hash,
	}, ""); err != nil {
		return err
	}
	if generated {
		slog.Info("created initial admin user — change this password in the UI",
			"username", "admin", "password", adminPassword)
	} else {
		slog.Info("created initial admin user", "username", "admin")
	}
	return nil
}

// ResetAdmin sets the admin account's password, creating the account if it
// is missing, and returns the password actually set. An empty password
// generates a strong random one. It also re-enables the account, restores
// its admin role, and revokes existing sessions — so it doubles as a
// lockout-recovery path for anyone with database/container access (run via
// `syslog-bucket reset-admin` or `scripts/yardctl reset-admin`).
func ResetAdmin(ctx context.Context, st *store.Store, password string) (string, error) {
	if password == "" {
		password = generatePassword()
	} else if len(password) < minPassword {
		return "", fmt.Errorf("password must be at least %d characters", minPassword)
	}
	hash, err := HashPassword(password)
	if err != nil {
		return "", err
	}
	u, err := st.GetUserByUsername(ctx, "admin")
	if err != nil {
		return "", err
	}
	if u == nil {
		if _, err := st.CreateUser(ctx, store.User{
			Username: "admin", DisplayName: "Administrator", Role: store.RoleAdmin, PasswordHash: hash,
		}, ""); err != nil {
			return "", err
		}
		return password, nil
	}
	if _, err := st.UpdateUser(ctx, u.ID, u.DisplayName, u.Email, store.RoleAdmin, false); err != nil {
		return "", err
	}
	if _, err := st.SetPassword(ctx, u.ID, hash); err != nil {
		return "", err
	}
	if err := st.DeleteUserSessions(ctx, u.ID); err != nil {
		return "", err
	}
	return password, nil
}

func HashPassword(pw string) (string, error) {
	h, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	return string(h), err
}

// dummyHash is a bcrypt hash of a random throwaway password at the same cost
// as real ones. Logins for unknown, disabled, or OIDC-only accounts are
// compared against it, so every failure costs one bcrypt and response timing
// doesn't reveal which usernames exist.
var dummyHash = sync.OnceValue(func() []byte {
	h, err := bcrypt.GenerateFromPassword([]byte(randHex(16)), bcrypt.DefaultCost)
	if err != nil {
		panic("auth: generate dummy bcrypt hash: " + err.Error())
	}
	return h
})

// checkPassword reports whether pw signs u in: an enabled local account
// whose bcrypt hash matches. It always runs exactly one bcrypt comparison.
func checkPassword(u *store.User, pw string) bool {
	hash := dummyHash()
	usable := u != nil && !u.Disabled && u.PasswordHash != ""
	if u != nil && u.PasswordHash != "" {
		hash = []byte(u.PasswordHash)
	}
	return bcrypt.CompareHashAndPassword(hash, []byte(pw)) == nil && usable
}

func tooManyAttempts(w http.ResponseWriter, retry time.Duration) {
	w.Header().Set("Retry-After", strconv.Itoa(int(retry.Seconds())+1))
	http.Error(w, "too many failed attempts — try again later", http.StatusTooManyRequests)
}

// generatedPasswordBytes is the entropy of generated admin passwords: 128
// bits, printed as 32 hex characters.
const generatedPasswordBytes = 16

func generatePassword() string { return randHex(generatedPasswordBytes) }

func randHex(nBytes int) string {
	b := make([]byte, nBytes)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func hashToken(tok string) string {
	sum := sha256.Sum256([]byte(tok))
	return hex.EncodeToString(sum[:])
}

// --- request context ---

type ctxKey struct{}

// UserFrom returns the authenticated user, or nil on public paths.
func UserFrom(ctx context.Context) *store.User {
	u, _ := ctx.Value(ctxKey{}).(*store.User)
	return u
}

// WithUser returns ctx carrying u as the authenticated user, as Middleware
// does after resolving a session. It lets tests drive the router as a given
// role without a database.
func WithUser(ctx context.Context, u *store.User) context.Context {
	return context.WithValue(ctx, ctxKey{}, u)
}

// publicAPI lists /api/ paths reachable without a session: liveness, the
// yard nav hints, and everything the login page itself needs.
var publicAPI = map[string]bool{
	"/api/healthz":            true,
	"/api/hints":              true,
	"/api/auth/info":          true,
	"/api/auth/login":         true,
	"/api/auth/oidc/login":    true,
	"/api/auth/oidc/callback": true,
}

// viewerWritable are the only non-GET paths a read-only viewer may call.
var viewerWritable = map[string]bool{
	"/api/auth/logout":   true,
	"/api/auth/password": true,
}

// Middleware resolves the session cookie into a user on every request,
// rejects anonymous access to the API, and enforces the viewer role's
// read-only contract in one place. Static SPA files stay public — the SPA
// renders the login screen itself.
func (s *Service) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if c, err := r.Cookie(sessionCookie); err == nil {
			tokenHash := hashToken(c.Value)
			u, err := s.store.GetSessionUser(r.Context(), tokenHash)
			if err != nil {
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			if u != nil {
				r = r.WithContext(context.WithValue(r.Context(), ctxKey{}, u))
				// Inactivity timeout: a request is activity, so push the expiry
				// forward (throttled in the store). Refresh the cookie's Max-Age
				// to match when it actually moved.
				idle := s.currentIdle()
				if slid, _ := s.store.SlideSession(r.Context(), tokenHash, idle); slid {
					s.setSessionCookie(w, c.Value, idle)
				}
			}
		}
		if strings.HasPrefix(r.URL.Path, "/api/") && !publicAPI[r.URL.Path] {
			u := UserFrom(r.Context())
			if u == nil {
				http.Error(w, "authentication required", http.StatusUnauthorized)
				return
			}
			if u.Role == store.RoleViewer && r.Method != http.MethodGet && r.Method != http.MethodHead &&
				!viewerWritable[r.URL.Path] {
				http.Error(w, "read-only role", http.StatusForbidden)
				return
			}
		}
		if strings.HasPrefix(r.URL.Path, "/api/") && !csrfSafe(r) {
			http.Error(w, "Content-Type must be application/json", http.StatusUnsupportedMediaType)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// csrfSafe rejects the one kind of state-changing request a foreign page can
// send without a CORS preflight: a POST with a "simple" content type
// (text/plain, form-encoded, multipart). SameSite=Lax doesn't cover it when
// the page is same-site — any other port on the same host, e.g. another app
// on localhost — so the cookie would ride along. PUT/PATCH/DELETE and JSON
// POSTs are always preflighted cross-origin, which the API never answers.
// Logout stays exempt: it has no body, and forcing one is harmless.
func csrfSafe(r *http.Request) bool {
	if r.Method != http.MethodPost || r.URL.Path == "/api/auth/logout" {
		return true
	}
	mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	return err == nil && mt == "application/json"
}

// SessionActive reports whether r's session cookie still belongs to a live
// session of an enabled user. Long-lived streams (the live tail) poll it,
// since the middleware only checks once at the start. Database errors count
// as inactive; the client simply reconnects.
func (s *Service) SessionActive(ctx context.Context, r *http.Request) bool {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return false
	}
	u, err := s.store.GetSessionUser(ctx, hashToken(c.Value))
	return err == nil && u != nil
}

// --- session plumbing ---

func (s *Service) issueSession(ctx context.Context, w http.ResponseWriter, userID int64) error {
	idle := s.currentIdle()
	token := randHex(32)
	if err := s.store.CreateSession(ctx, hashToken(token), userID, time.Now().Add(idle)); err != nil {
		return err
	}
	s.setSessionCookie(w, token, idle)
	return nil
}

func (s *Service) setSessionCookie(w http.ResponseWriter, token string, idle time.Duration) {
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: token, Path: "/",
		MaxAge: int(idle.Seconds()), HttpOnly: true,
		SameSite: http.SameSiteLaxMode, Secure: s.cookieSecure,
	})
}

// --- handlers (mounted by the api package) ---

func (s *Service) HandleLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	key, ip := strings.ToLower(strings.TrimSpace(req.Username)), s.clientIP(r)
	if ok, retry := s.loginGuard.allow(key, ip); !ok {
		tooManyAttempts(w, retry)
		return
	}
	u, err := s.store.GetUserByUsername(r.Context(), strings.TrimSpace(req.Username))
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if !checkPassword(u, req.Password) {
		s.loginGuard.fail(key, ip)
		// Flat delay + uniform message: no username/password oracle.
		time.Sleep(500 * time.Millisecond)
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}
	s.loginGuard.succeed(key, ip)
	if err := s.issueSession(r.Context(), w, u.ID); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, u)
}

func (s *Service) HandleLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil {
		s.store.DeleteSession(r.Context(), hashToken(c.Value))
	}
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, SameSite: http.SameSiteLaxMode, Secure: s.cookieSecure,
	})
	w.WriteHeader(http.StatusNoContent)
}

func (s *Service) HandleMe(w http.ResponseWriter, r *http.Request) {
	u := UserFrom(r.Context())
	if u == nil {
		http.Error(w, "authentication required", http.StatusUnauthorized)
		return
	}
	writeJSON(w, u)
}

// HandleInfo tells the (pre-auth) login page which sign-in methods exist.
func (s *Service) HandleInfo(w http.ResponseWriter, _ *http.Request) {
	o := s.currentOIDC()
	info := map[string]any{"oidc": map[string]any{"enabled": false}}
	if o != nil {
		info["oidc"] = map[string]any{"enabled": true, "name": o.Name}
	}
	writeJSON(w, info)
}

// HandlePassword lets any signed-in local user change their own password.
// All sessions are revoked and one fresh session is issued, so a stolen
// session dies with the old password.
func (s *Service) HandlePassword(w http.ResponseWriter, r *http.Request) {
	u := UserFrom(r.Context())
	var req struct {
		Old string `json:"old"`
		New string `json:"new"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	if u.PasswordHash == "" {
		http.Error(w, "this account signs in via OIDC", http.StatusBadRequest)
		return
	}
	// The old password is a guessable secret too: throttle it like a login so
	// a stolen session can't be used to brute-force the real password.
	key, ip := "id:"+strconv.FormatInt(u.ID, 10), s.clientIP(r)
	if ok, retry := s.pwGuard.allow(key, ip); !ok {
		tooManyAttempts(w, retry)
		return
	}
	if !checkPassword(u, req.Old) {
		s.pwGuard.fail(key, ip)
		http.Error(w, "current password is incorrect", http.StatusForbidden)
		return
	}
	s.pwGuard.succeed(key, ip)
	if len(req.New) < minPassword {
		http.Error(w, "new password must be at least 8 characters", http.StatusBadRequest)
		return
	}
	hash, err := HashPassword(req.New)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if _, err := s.store.SetPassword(r.Context(), u.ID, hash); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	s.store.DeleteUserSessions(r.Context(), u.ID)
	if err := s.issueSession(r.Context(), w, u.ID); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}
