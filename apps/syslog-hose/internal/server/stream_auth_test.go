package server

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/syslog-yard/shared/yardauth"
)

// streamEnds reports whether an open /api/stream ends on its own within d.
func streamEnds(t *testing.T, url string, d time.Duration) bool {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", url+"/api/stream", nil)
	req.AddCookie(&http.Cookie{Name: "bucket_session", Value: "tok"})
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("open stream: %d", resp.StatusCode)
	}
	_, err = io.Copy(io.Discard, resp.Body)
	return err == nil
}

func streamFixture(t *testing.T) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var status atomic.Int32
	bucket := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if code := int(status.Load()); code != 0 {
			http.Error(w, "no", code)
			return
		}
		w.Write([]byte(`{"id":1,"username":"u","role":"viewer"}`))
	}))
	t.Cleanup(bucket.Close)
	guard := yardauth.New(bucket.URL, false)
	guard.SetSessionRecheck(10 * time.Millisecond)
	return newTestServer(t, guard), &status
}

func TestStreamEndsWhenSessionRevoked(t *testing.T) {
	ts, status := streamFixture(t)
	timer := time.AfterFunc(100*time.Millisecond, func() { status.Store(http.StatusUnauthorized) })
	defer timer.Stop()
	if !streamEnds(t, ts.URL, 5*time.Second) {
		t.Fatal("stream kept running after the session was revoked")
	}
}

func TestStreamSurvivesBucketOutage(t *testing.T) {
	ts, status := streamFixture(t)
	timer := time.AfterFunc(50*time.Millisecond, func() { status.Store(http.StatusServiceUnavailable) })
	defer timer.Stop()
	if streamEnds(t, ts.URL, 500*time.Millisecond) {
		t.Fatal("stream ended on a transient bucket outage")
	}
}
