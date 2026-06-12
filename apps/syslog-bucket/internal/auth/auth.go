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
	"net/http"
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

	// Brute-force throttle: lock an account's login for loginWindow after
	// loginMaxFails consecutive bad passwords.
	loginMaxFails = 10
	loginWindow   = 5 * time.Minute
)

type Service struct {
	store        *store.Store
	cookieSecure bool
	loginLimiter *throttle

	// oidc and idleTTL are runtime-configurable from the admin settings UI, so
	// they're guarded rather than fixed at construction.
	mu      sync.RWMutex
	oidc    *OIDC // nil = OIDC disabled
	idleTTL time.Duration
}

func New(st *store.Store, cookieSecure bool) *Service {
	return &Service{
		store:        st,
		cookieSecure: cookieSecure,
		loginLimiter: newThrottle(loginMaxFails, loginWindow),
		idleTTL:      defaultIdleTTL,
	}
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
		adminPassword = randHex(8)
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
		password = randHex(8)
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
		next.ServeHTTP(w, r)
	})
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
	key := strings.ToLower(strings.TrimSpace(req.Username))
	if ok, retry := s.loginLimiter.allow(key); !ok {
		w.Header().Set("Retry-After", strconv.Itoa(int(retry.Seconds())+1))
		http.Error(w, "too many failed attempts — try again later", http.StatusTooManyRequests)
		return
	}
	u, err := s.store.GetUserByUsername(r.Context(), strings.TrimSpace(req.Username))
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if u == nil || u.Disabled || u.PasswordHash == "" ||
		bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(req.Password)) != nil {
		s.loginLimiter.fail(key)
		// Flat delay + uniform message: no username/password oracle.
		time.Sleep(500 * time.Millisecond)
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}
	s.loginLimiter.reset(key)
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
	if bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(req.Old)) != nil {
		http.Error(w, "current password is incorrect", http.StatusForbidden)
		return
	}
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
