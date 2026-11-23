package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/syslog-yard/shared/yardauth"
	"github.com/syslog-yard/syslog-valve/internal/tap"
)

const secretPath = "/services/T000/SECRETTOKEN"

// roleBucket maps tokens named tok-<role> to a user of that role; status
// overrides every answer while non-zero.
func roleBucket(t *testing.T) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var status atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if code := int(status.Load()); code != 0 {
			http.Error(w, "no", code)
			return
		}
		c, err := r.Cookie("bucket_session")
		if err != nil || !strings.HasPrefix(c.Value, "tok-") {
			http.Error(w, "authentication required", http.StatusUnauthorized)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"id": 1, "username": "u", "role": strings.TrimPrefix(c.Value, "tok-")})
	}))
	t.Cleanup(srv.Close)
	return srv, &status
}

// guarded returns a server over e's data dir that enforces yard auth.
func (e *env) guarded(bucketURL string) (*Server, *yardauth.Guard) {
	g := yardauth.New(bucketURL, false)
	g.SetSessionRecheck(10 * time.Millisecond)
	return New(e.sup, e.dataDir, nil, nil, nil, e.rotator, tap.New(), e.nd, g), g
}

func as(srv *Server, token, method, path string, body []byte) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, bytes.NewReader(body))
	if len(body) > 0 {
		r.Header.Set("Content-Type", "application/json")
	}
	r.AddCookie(&http.Cookie{Name: "bucket_session", Value: token})
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, r)
	return w
}

func secretFlow() []byte {
	return bytes.ReplaceAll(flow("one", true, 6514), []byte("/hook"), []byte(secretPath))
}

func TestViewerNeverReceivesNotifyURL(t *testing.T) {
	e := newEnv(t)
	e.mustOK("PUT", "/api/graph", secretFlow())
	e.mustOK("POST", "/api/apply", nil)
	bucket, _ := roleBucket(t)
	srv, _ := e.guarded(bucket.URL)

	paths := []string{"/api/graph", "/api/config", "/api/history", "/api/status", "/api/notify/log", "/api/notify/stats"}
	for _, h := range e.history() {
		paths = append(paths, "/api/history/"+h.ID+"/config")
	}
	for _, p := range paths {
		w := as(srv, "tok-viewer", "GET", p, nil)
		if w.Code != http.StatusOK {
			t.Fatalf("GET %s: %d %s", p, w.Code, w.Body)
		}
		if strings.Contains(w.Body.String(), "SECRETTOKEN") {
			t.Errorf("GET %s leaked the notify URL to a viewer: %s", p, w.Body)
		}
	}

	w := as(srv, "tok-viewer", "GET", "/api/graph", nil)
	var got struct {
		Nodes []struct {
			ID     string `json:"id"`
			Config struct {
				URL    string `json:"url"`
				HasURL bool   `json:"has_url"`
			} `json:"config"`
		} `json:"nodes"`
		Edges []any `json:"edges"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Nodes) != 3 || len(got.Edges) != 2 {
		t.Fatalf("viewer graph lost structure: %s", w.Body)
	}
	for _, n := range got.Nodes {
		if n.ID == "notify-1" && (n.Config.URL != "http://127.0.0.1/…" || !n.Config.HasURL) {
			t.Fatalf("viewer notify config = %+v", n.Config)
		}
	}

	for _, role := range []string{"tok-admin", "tok-analyst"} {
		if w := as(srv, role, "GET", "/api/graph", nil); !strings.Contains(w.Body.String(), secretPath) {
			t.Errorf("%s did not get the full URL: %s", role, w.Body)
		}
	}
}

func TestViewerGraphWithUnreadableStoreLeaksNothing(t *testing.T) {
	e := newEnv(t)
	bucket, _ := roleBucket(t)
	srv, _ := e.guarded(bucket.URL)
	if err := atomicWrite(srv.graphPath, []byte(`{"nodes":[{"config":{"url":"http://x`+secretPath+`"}}`)); err != nil {
		t.Fatal(err)
	}
	w := as(srv, "tok-viewer", "GET", "/api/graph", nil)
	if w.Code != http.StatusInternalServerError || strings.Contains(w.Body.String(), "SECRETTOKEN") {
		t.Fatalf("got %d %s", w.Code, w.Body)
	}
}

func TestEditorSavingMaskedGraphKeepsStoredURL(t *testing.T) {
	e := newEnv(t)
	e.mustOK("PUT", "/api/graph", secretFlow())
	bucket, _ := roleBucket(t)
	srv, _ := e.guarded(bucket.URL)

	// A graph loaded while the user was a viewer, saved after a promotion.
	masked := as(srv, "tok-viewer", "GET", "/api/graph", nil).Body.Bytes()
	if w := as(srv, "tok-analyst", "PUT", "/api/graph", masked); w.Code != http.StatusOK {
		t.Fatalf("save masked graph: %d %s", w.Code, w.Body)
	}
	stored := e.read("graph.json")
	if !strings.Contains(stored, secretPath) || strings.Contains(stored, "…") {
		t.Fatalf("stored URL changed: %s", stored)
	}

	// A mask with no matching stored node can't be resolved: refuse it.
	other := bytes.ReplaceAll(masked, []byte("notify-1"), []byte("notify-2"))
	if w := as(srv, "tok-analyst", "PUT", "/api/graph", other); w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("unmatched mask: %d %s", w.Code, w.Body)
	}
	// Nor may a mask of a different host pick up the stored secret.
	moved := bytes.ReplaceAll(masked, []byte("127.0.0.1"), []byte("127.0.0.2"))
	if w := as(srv, "tok-analyst", "PUT", "/api/graph", moved); w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("mask of another host: %d %s", w.Code, w.Body)
	}
	if got := e.read("graph.json"); got != stored {
		t.Fatalf("refused save changed the store: %s", got)
	}

	// A real new URL still replaces the stored one.
	if w := as(srv, "tok-analyst", "PUT", "/api/graph", flow("one", true, 6514)); w.Code != http.StatusOK {
		t.Fatalf("save new URL: %d %s", w.Code, w.Body)
	}
	if got := e.read("graph.json"); strings.Contains(got, "SECRETTOKEN") {
		t.Fatalf("new URL not saved: %s", got)
	}
}

func TestNotifyTestRefusesMaskedURL(t *testing.T) {
	e := newEnv(t)
	bucket, _ := roleBucket(t)
	srv, _ := e.guarded(bucket.URL)
	w := as(srv, "tok-analyst", "POST", "/api/notify/test", []byte(`{"kind":"webhook","url":"http://127.0.0.1/…"}`))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("got %d %s", w.Code, w.Body)
	}
}

// tailEnds reports whether an open /api/tail ends on its own within d.
func tailEnds(t *testing.T, url string, d time.Duration) bool {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", url+"/api/tail", nil)
	req.AddCookie(&http.Cookie{Name: "bucket_session", Value: "tok-viewer"})
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	_, err = io.Copy(io.Discard, resp.Body)
	return err == nil
}

func TestTailEndsWhenSessionRevoked(t *testing.T) {
	e := newEnv(t)
	bucket, status := roleBucket(t)
	srv, _ := e.guarded(bucket.URL)
	ts := httptest.NewServer(srv)
	defer ts.Close()
	timer := time.AfterFunc(100*time.Millisecond, func() { status.Store(http.StatusUnauthorized) })
	defer timer.Stop()
	if !tailEnds(t, ts.URL, 5*time.Second) {
		t.Fatal("tail kept running after the session was revoked")
	}
}

func TestTailSurvivesBucketOutage(t *testing.T) {
	e := newEnv(t)
	bucket, status := roleBucket(t)
	srv, _ := e.guarded(bucket.URL)
	ts := httptest.NewServer(srv)
	defer ts.Close()
	timer := time.AfterFunc(50*time.Millisecond, func() { status.Store(http.StatusServiceUnavailable) })
	defer timer.Stop()
	if tailEnds(t, ts.URL, 500*time.Millisecond) {
		t.Fatal("tail ended on a transient bucket outage")
	}
}
