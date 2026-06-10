package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/syslog-yard/syslog-bucket/internal/store"
)

// The middleware's allow/deny decisions for anonymous requests and for the
// viewer role need no database — no cookie means no session lookup.
func TestMiddlewareGating(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	svc := New(nil, nil, false)
	h := svc.Middleware(next)

	cases := []struct {
		method, path string
		user         *store.User
		want         int
	}{
		{"GET", "/api/entries", nil, http.StatusUnauthorized},
		{"POST", "/api/buckets", nil, http.StatusUnauthorized},
		{"GET", "/api/healthz", nil, http.StatusOK},
		{"GET", "/api/hints", nil, http.StatusOK},
		{"GET", "/api/auth/info", nil, http.StatusOK},
		{"POST", "/api/auth/login", nil, http.StatusOK},
		{"GET", "/", nil, http.StatusOK}, // SPA stays public; it renders the login screen
		{"GET", "/api/entries", &store.User{Role: store.RoleViewer}, http.StatusOK},
		{"POST", "/api/buckets", &store.User{Role: store.RoleViewer}, http.StatusForbidden},
		{"PATCH", "/api/entries/1", &store.User{Role: store.RoleViewer}, http.StatusForbidden},
		{"POST", "/api/auth/logout", &store.User{Role: store.RoleViewer}, http.StatusOK},
		{"PUT", "/api/auth/password", &store.User{Role: store.RoleViewer}, http.StatusOK},
		{"POST", "/api/buckets", &store.User{Role: store.RoleAnalyst}, http.StatusOK},
	}
	for _, c := range cases {
		r := httptest.NewRequest(c.method, c.path, nil)
		if c.user != nil {
			r = r.WithContext(context.WithValue(r.Context(), ctxKey{}, c.user))
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != c.want {
			t.Errorf("%s %s (user=%v): got %d, want %d", c.method, c.path, c.user, w.Code, c.want)
		}
	}
}
