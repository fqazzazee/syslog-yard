package notify

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/syslog-yard/syslog-bucket/internal/store"
)

func TestShutdownDeliversQueuedThenStops(t *testing.T) {
	var mu sync.Mutex
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		mu.Lock()
		hits++
		mu.Unlock()
	}))
	defer srv.Close()
	d := New(nil)
	d.allowLoopback = true
	d.channels[1] = store.Channel{ID: 1, Kind: "slack", Enabled: true, Config: json.RawMessage(`{"url":"` + srv.URL + `"}`)}
	ctx, cancel := context.WithCancel(context.Background())
	go d.Run(ctx)
	var batch []store.Entry
	for i := 0; i < 10; i++ {
		batch = append(batch, store.Entry{ID: int64(i), Notifies: []store.Notify{{ChannelID: 1}}})
	}
	d.Dispatch(batch)
	cancel() // the process is stopping: queued deliveries must still go out
	d.Shutdown(5 * time.Second)
	mu.Lock()
	defer mu.Unlock()
	if hits != 10 {
		t.Errorf("delivered %d of 10 queued notifications", hits)
	}
	d.Dispatch(batch) // after Shutdown: counted as dropped, no panic
}

func TestShutdownAbandonsSlowDeliveries(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { <-release }))
	defer srv.Close()
	defer close(release)
	d := New(nil)
	d.allowLoopback = true
	d.channels[1] = store.Channel{ID: 1, Kind: "slack", Enabled: true, Config: json.RawMessage(`{"url":"` + srv.URL + `"}`)}
	go d.Run(context.Background())
	var batch []store.Entry
	for i := 0; i < 50; i++ {
		batch = append(batch, store.Entry{ID: int64(i), Notifies: []store.Notify{{ChannelID: 1}}})
	}
	d.Dispatch(batch)
	start := time.Now()
	d.Shutdown(200 * time.Millisecond)
	if el := time.Since(start); el > 2*time.Second {
		t.Errorf("Shutdown took %v", el)
	}
}
