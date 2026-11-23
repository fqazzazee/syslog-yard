package yardauth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// switchBucket answers /api/auth/me with a settable status, and with a
// refreshed session cookie while slide is set.
type switchBucket struct {
	status atomic.Int32
	slide  atomic.Bool
	calls  atomic.Int32
	srv    *httptest.Server
}

func newSwitchBucket(t *testing.T) *switchBucket {
	t.Helper()
	b := &switchBucket{}
	b.status.Store(http.StatusOK)
	b.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b.calls.Add(1)
		code := int(b.status.Load())
		if code != http.StatusOK {
			http.Error(w, "no", code)
			return
		}
		if c, err := r.Cookie(cookieName); err == nil && b.slide.Load() {
			http.SetCookie(w, &http.Cookie{Name: cookieName, Value: c.Value, Path: "/", MaxAge: 1800})
		}
		w.Write([]byte(`{"id":7,"username":"alice","role":"analyst"}`))
	}))
	t.Cleanup(b.srv.Close)
	return b
}

// through runs one request with the token through the guard, handing the
// handler's request to inspect.
func through(g *Guard, token string, inspect func(*http.Request)) *httptest.ResponseRecorder {
	h := g.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if inspect != nil {
			inspect(r)
		}
	}))
	r := httptest.NewRequest("GET", "/api/jobs", nil)
	r.AddCookie(&http.Cookie{Name: cookieName, Value: token})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

// watch opens a session watch as a stream handler would, outliving the
// middleware call.
func watch(t *testing.T, g *Guard, token string) context.Context {
	t.Helper()
	parent, cancelParent := context.WithCancel(context.Background())
	t.Cleanup(cancelParent)
	var ctx context.Context
	through(g, token, func(r *http.Request) {
		var stop context.CancelFunc
		ctx, stop = WatchSession(r.WithContext(context.WithoutCancel(r.Context())))
		t.Cleanup(stop)
		context.AfterFunc(parent, stop)
	})
	if ctx == nil {
		t.Fatal("request did not reach the handler")
	}
	return ctx
}

func sessionCookieOf(w *httptest.ResponseRecorder) *http.Cookie {
	for _, c := range w.Result().Cookies() {
		if c.Name == cookieName {
			return c
		}
	}
	return nil
}

func TestUserFromCarriesVerifiedUser(t *testing.T) {
	b := newSwitchBucket(t)
	var got *User
	through(New(b.srv.URL, false), "tok", func(r *http.Request) { got = UserFrom(r.Context()) })
	if got == nil || got.Username != "alice" || got.Role != "analyst" {
		t.Fatalf("UserFrom = %+v", got)
	}
}

func TestWatchSessionEndsOnRevocation(t *testing.T) {
	b := newSwitchBucket(t)
	g := New(b.srv.URL, false)
	g.SetSessionRecheck(10 * time.Millisecond)
	ctx := watch(t, g, "tok")
	b.status.Store(http.StatusUnauthorized)
	select {
	case <-ctx.Done():
	case <-time.After(3 * time.Second):
		t.Fatal("stream context survived a definite 401")
	}
}

func TestWatchSessionSurvivesBucketOutage(t *testing.T) {
	b := newSwitchBucket(t)
	g := New(b.srv.URL, false)
	g.SetSessionRecheck(10 * time.Millisecond)
	ctx := watch(t, g, "tok")
	for _, code := range []int32{http.StatusServiceUnavailable, http.StatusInternalServerError, http.StatusBadGateway} {
		b.status.Store(code)
		before := b.calls.Load()
		deadline := time.Now().Add(3 * time.Second)
		for b.calls.Load() < before+3 && time.Now().Before(deadline) {
			time.Sleep(5 * time.Millisecond)
		}
		if ctx.Err() != nil {
			t.Fatalf("stream context ended on a transient %d", code)
		}
	}
}

func TestWatchSessionWithoutSessionStaysOpen(t *testing.T) {
	r := httptest.NewRequest("GET", "/api/stream", nil) // guard disabled: no session in context
	ctx, stop := WatchSession(r)
	defer stop()
	if ctx.Err() != nil {
		t.Fatal("context ended immediately")
	}
	stop()
	if ctx.Err() == nil {
		t.Fatal("stop did not cancel the context")
	}
}

func TestSlidSessionRefreshesBrowserCookie(t *testing.T) {
	b := newSwitchBucket(t)
	b.slide.Store(true)
	g := New(b.srv.URL, true)

	c := sessionCookieOf(through(g, "tok", nil))
	if c == nil || c.Value != "tok" || c.MaxAge <= 0 || c.MaxAge > 1800 || !c.HttpOnly || !c.Secure ||
		c.Path != "/" || c.SameSite != http.SameSiteLaxMode {
		t.Fatalf("refreshed cookie = %+v", c)
	}
	if c := sessionCookieOf(through(g, "tok", nil)); c != nil {
		t.Fatalf("cached request re-sent the cookie: %+v", c)
	}
}

// A stream's recheck may be the request that slides the session, and its
// response can't reach the browser, so the next request has to carry it.
func TestRecheckSlideReachesNextRequest(t *testing.T) {
	b := newSwitchBucket(t)
	g := New(b.srv.URL, false)
	g.SetSessionRecheck(10 * time.Millisecond)
	watch(t, g, "tok")
	before := b.calls.Load()
	b.slide.Store(true)
	deadline := time.Now().Add(3 * time.Second)
	for b.calls.Load() < before+2 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if c := sessionCookieOf(through(g, "tok", nil)); c == nil || c.MaxAge <= 0 {
		t.Fatalf("next request did not carry the refreshed cookie: %+v", c)
	}
}

func TestForeignCookieIsNotPropagated(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: cookieName, Value: "other", MaxAge: 1800})
		w.Write([]byte(`{"id":7,"username":"alice","role":"analyst"}`))
	}))
	defer srv.Close()
	if c := sessionCookieOf(through(New(srv.URL, false), "tok", nil)); c != nil {
		t.Fatalf("propagated a cookie for a different token: %+v", c)
	}
}
