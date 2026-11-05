package netfeeds

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// A failed fetch is retried on a short backoff, not left until the next
// regular check.
func TestRunRetriesFailedFetch(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if calls.Add(1) <= 2 {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		w.Write([]byte("203.0.113.7\n"))
	}))
	defer srv.Close()

	saved, savedMin, savedMax := builtins, retryMin, retryMax
	builtins = []feedDef{{ID: "t", Label: "t", Category: CatMalicious, URL: srv.URL, Parse: parsePlainIPs}}
	retryMin, retryMax = 10*time.Millisecond, 40*time.Millisecond
	defer func() { builtins, retryMin, retryMax = saved, savedMin, savedMax }()

	m := New(nil)
	ctx, cancel := context.WithCancel(context.Background())
	runDone := make(chan struct{})
	go func() { m.Run(ctx); close(runDone) }()
	defer func() { cancel(); <-runDone }() // before builtins are restored

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if st := m.Statuses(); len(st) == 1 && st[0].Prefixes == 1 && st[0].Error == "" {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("feed not refreshed after failures (calls=%d, status=%+v)", calls.Load(), m.Statuses())
}

// A refresh started from the API is detached from the request: cancelling
// the caller doesn't abort it or record "context canceled".
func TestRefreshInBackgroundOutlivesCaller(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(50 * time.Millisecond)
		w.Write([]byte("198.51.100.1\n"))
	}))
	defer srv.Close()
	saved := builtins
	builtins = []feedDef{{ID: "t", Label: "t", Category: CatMalicious, URL: srv.URL, Parse: parsePlainIPs}}
	defer func() { builtins = saved }()

	m := New(nil)
	hook := make(chan struct{})
	done := m.RefreshInBackground(true, func() { close(hook) })
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("background refresh did not finish")
	}
	<-hook
	if st := m.Statuses(); st[0].Prefixes != 1 || st[0].Error != "" {
		t.Errorf("status = %+v", st)
	}
}
