package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/syslog-yard/shared/yardauth"
	"github.com/syslog-yard/syslog-bucket/internal/store"
	"github.com/syslog-yard/syslog-bucket/internal/store/storetest"
)

func sessionCheckHandler(svc *Service) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/auth/me", svc.HandleMe)
	mux.HandleFunc("GET /api/auth/session", svc.HandleSessionCheck)
	return svc.Middleware(mux)
}

func sessionExpiry(t *testing.T, st *store.Store, token string) time.Time {
	t.Helper()
	var at time.Time
	if err := st.Pool.QueryRow(context.Background(),
		`SELECT expires_at FROM sessions WHERE token_hash = $1`, hashToken(token)).Scan(&at); err != nil {
		t.Fatal(err)
	}
	return at
}

func sessionUser(t *testing.T, st *store.Store) store.User {
	t.Helper()
	u, err := st.CreateUser(context.Background(), store.User{Username: "streamer", Role: store.RoleViewer}, "")
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func getWithSession(h http.Handler, path, token string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("GET", path, nil)
	r.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestSessionCheckDoesNotSlide(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	u := sessionUser(t, st)
	svc := New(st, false)
	svc.SetIdleTTL(time.Hour)
	h := sessionCheckHandler(svc)
	const token = "check-token"
	// Far enough from a full window that any sliding request would move it.
	if err := st.CreateSession(ctx, hashToken(token), u.ID, time.Now().Add(10*time.Minute)); err != nil {
		t.Fatal(err)
	}
	before := sessionExpiry(t, st, token)

	for range 5 {
		w := getWithSession(h, "/api/auth/session", token)
		if w.Code != http.StatusNoContent {
			t.Fatalf("check = %d", w.Code)
		}
		if c := w.Result().Cookies(); len(c) != 0 {
			t.Fatalf("check set a cookie: %+v", c)
		}
	}
	if after := sessionExpiry(t, st, token); !after.Equal(before) {
		t.Fatalf("check moved expires_at from %v to %v", before, after)
	}

	// Control: an ordinary request still slides the same session.
	if w := getWithSession(h, "/api/auth/me", token); w.Code != http.StatusOK {
		t.Fatalf("me = %d", w.Code)
	}
	if after := sessionExpiry(t, st, token); !after.After(before) {
		t.Fatal("control: /api/auth/me did not slide the session")
	}
}

func TestSessionCheckRejectsDeadSession(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	u := sessionUser(t, st)
	h := sessionCheckHandler(New(st, false))
	if err := st.CreateSession(ctx, hashToken("expired"), u.ID, time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	for _, token := range []string{"expired", "unknown"} {
		if w := getWithSession(h, "/api/auth/session", token); w.Code != http.StatusUnauthorized {
			t.Errorf("%s: check = %d, want 401", token, w.Code)
		}
	}
}

// An open stream, rechecking through the real guard, neither keeps the
// session alive nor outlives its idle expiry.
func TestIdleSessionEndsStream(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	u := sessionUser(t, st)
	svc := New(st, false)
	svc.SetIdleTTL(4 * time.Second)
	bucket := httptest.NewServer(sessionCheckHandler(svc))
	defer bucket.Close()
	const token = "stream-token"
	if err := st.CreateSession(ctx, hashToken(token), u.ID, time.Now().Add(4*time.Second)); err != nil {
		t.Fatal(err)
	}

	g := yardauth.New(bucket.URL, false)
	g.SetSessionRecheck(50 * time.Millisecond)
	var before time.Time
	ended := false
	h := g.Middleware(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		// Opening the stream is a real request and may slide; only what
		// happens after this point is the stream's doing.
		before = sessionExpiry(t, st, token)
		streamCtx, stop := yardauth.WatchSession(r)
		defer stop()
		select {
		case <-streamCtx.Done():
			ended = true
		case <-time.After(12 * time.Second):
		}
	}))
	r := httptest.NewRequest("GET", "/api/stream", nil)
	r.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
	h.ServeHTTP(httptest.NewRecorder(), r)
	if !ended {
		t.Fatal("stream outlived the idle timeout")
	}
	if after := sessionExpiry(t, st, token); !after.Equal(before) {
		t.Fatalf("stream moved expires_at from %v to %v", before, after)
	}
}
