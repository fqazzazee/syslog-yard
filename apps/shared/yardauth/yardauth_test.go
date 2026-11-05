package yardauth

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// fakeBucket stands in for syslog-bucket's auth API: one valid token, one
// valid credential pair.
func fakeBucket(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/auth/me", func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie("bucket_session")
		if err != nil || c.Value != "tok-good" {
			http.Error(w, "authentication required", http.StatusUnauthorized)
			return
		}
		w.Write([]byte(`{"id":7,"username":"alice","display_name":"","role":"viewer"}`))
	})
	mux.HandleFunc("POST /api/auth/login", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "bucket_session", Value: "tok-good", MaxAge: 3600})
		w.Write([]byte(`{"id":7,"username":"alice","display_name":"","role":"viewer"}`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestGuardDisabledPassesThrough(t *testing.T) {
	g := New("", false)
	h := g.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) }))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("POST", "/api/jobs", nil))
	if w.Code != 200 {
		t.Fatalf("disabled guard blocked request: %d", w.Code)
	}
}

func TestGuardEnforcement(t *testing.T) {
	bucket := fakeBucket(t)
	g := New(bucket.URL, false)
	h := g.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) }))

	cases := []struct {
		method, path, token string
		want                int
	}{
		{"GET", "/api/jobs", "", 401},
		{"GET", "/api/jobs", "tok-bad", 401},
		{"GET", "/api/jobs", "tok-good", 200},  // viewer may read
		{"POST", "/api/jobs", "tok-good", 403}, // viewer may not write
		{"GET", "/api/hints", "", 200},         // public
		{"GET", "/", "", 200},                  // SPA stays open
		{"GET", "/api/auth/info", "", 200},     // self-managing route
	}
	for _, c := range cases {
		r := httptest.NewRequest(c.method, c.path, nil)
		if c.token != "" {
			r.AddCookie(&http.Cookie{Name: "bucket_session", Value: c.token})
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != c.want {
			t.Errorf("%s %s token=%q: got %d, want %d", c.method, c.path, c.token, w.Code, c.want)
		}
	}
}

func TestLoginProxyReissuesCookie(t *testing.T) {
	bucket := fakeBucket(t)
	g := New(bucket.URL, false)
	mux := http.NewServeMux()
	g.Routes(mux)

	r := httptest.NewRequest("POST", "/api/auth/login", strings.NewReader(`{"username":"alice","password":"pw"}`))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("login: got %d: %s", w.Code, w.Body.String())
	}
	var got *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == "bucket_session" {
			got = c
		}
	}
	if got == nil || got.Value != "tok-good" || !got.HttpOnly {
		t.Fatalf("login did not re-issue the bucket session cookie: %+v", got)
	}
	if !strings.Contains(w.Body.String(), `"alice"`) {
		t.Fatalf("login did not relay the user body: %s", w.Body.String())
	}
}

func TestVerifyCaches(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Write([]byte(`{"id":1,"username":"a","role":"admin"}`))
	}))
	defer srv.Close()
	g := New(srv.URL, false)
	for range 5 {
		if _, err := g.verify(t.Context(), "tok"); err != nil {
			t.Fatal(err)
		}
	}
	if calls != 1 {
		t.Fatalf("expected 1 upstream call (cached), got %d", calls)
	}
}

// recordingBucket answers every request 200 and records what reached it.
type seen struct{ method, path, rawPath, xff string }

func recordingBucket(t *testing.T) (*httptest.Server, *[]seen) {
	t.Helper()
	var mu sync.Mutex
	got := &[]seen{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		*got = append(*got, seen{r.Method, r.URL.Path, r.URL.RawPath, r.Header.Get("X-Forwarded-For")})
		mu.Unlock()
		if r.URL.Path == "/api/auth/login" {
			http.SetCookie(w, &http.Cookie{Name: "bucket_session", Value: "tok"})
		}
		w.Write([]byte(`{}`))
	}))
	t.Cleanup(srv.Close)
	return srv, got
}

func TestProxyRejectsPathTraversal(t *testing.T) {
	bucket, got := recordingBucket(t)
	mux := http.NewServeMux()
	New(bucket.URL, false).Routes(mux)

	cases := []struct {
		method, target string
		want           int
		upstream       string
	}{
		{"PUT", "/api/users/12", 200, "/api/users/12"},
		{"DELETE", "/api/users/12", 200, "/api/users/12"},
		{"PUT", "/api/users/..%2F..%2Fapi%2Fsettings", 400, ""},
		{"PUT", "/api/users/..%2Fsettings%2Foidc", 400, ""},
		{"DELETE", "/api/users/1%2F..%2F..%2Fapi%2Fbuckets%2F1", 400, ""},
		{"PUT", "/api/users/0", 400, ""},
		{"PUT", "/api/users/-3", 400, ""},
		{"PUT", "/api/users/0x10", 400, ""},
		{"PUT", "/api/users/012", 200, "/api/users/12"}, // canonicalised
		{"GET", "/api/users", 200, "/api/users"},
		{"PUT", "/api/auth/password", 200, "/api/auth/password"},
	}
	for _, c := range cases {
		*got = nil
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, httptest.NewRequest(c.method, c.target, strings.NewReader(`{}`)))
		if w.Code != c.want {
			t.Errorf("%s %s: got %d, want %d", c.method, c.target, w.Code, c.want)
			continue
		}
		switch {
		case c.upstream == "" && len(*got) != 0:
			t.Errorf("%s %s: reached bucket at %+v", c.method, c.target, *got)
		case c.upstream != "" && (len(*got) != 1 || (*got)[0].path != c.upstream || (*got)[0].rawPath != ""):
			t.Errorf("%s %s: upstream %+v, want %s", c.method, c.target, *got, c.upstream)
		}
	}
}

func TestLoginAndProxyForwardClientIP(t *testing.T) {
	bucket, got := recordingBucket(t)
	mux := http.NewServeMux()
	New(bucket.URL, false).Routes(mux)

	for _, c := range []struct{ method, path string }{
		{"POST", "/api/auth/login"},
		{"PUT", "/api/auth/password"},
	} {
		*got = nil
		r := httptest.NewRequest(c.method, c.path, strings.NewReader(`{}`))
		r.RemoteAddr = "198.51.100.7:40000"
		r.Header.Set("X-Forwarded-For", "6.6.6.6") // spoof attempt from an untrusted peer
		mux.ServeHTTP(httptest.NewRecorder(), r)
		if len(*got) != 1 || (*got)[0].xff != "198.51.100.7" {
			t.Errorf("%s: upstream saw %+v, want X-Forwarded-For 198.51.100.7", c.path, *got)
		}
	}
}

func TestHealthzIsPublic(t *testing.T) {
	bucket := fakeBucket(t)
	h := New(bucket.URL, false).Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) }))
	for _, m := range []string{"GET", "HEAD"} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(m, "/api/healthz", nil))
		if w.Code != 200 {
			t.Errorf("%s /api/healthz without a session: got %d, want 200", m, w.Code)
		}
	}
}
