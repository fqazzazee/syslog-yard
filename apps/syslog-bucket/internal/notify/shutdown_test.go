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
	"github.com/syslog-yard/syslog-bucket/internal/store/storetest"
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
	d.guard.AllowLoopback = true
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

// A rate-limited storm leaves one summary row per (channel, rule), not one
// row per refused delivery.
func TestRateLimitedDropsAggregateInLogPG(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()
	ch, err := st.CreateChannel(ctx, store.Channel{Name: "c", Kind: "slack", Enabled: true, RatePerMin: 2,
		Config: json.RawMessage(`{"url":"` + srv.URL + `"}`)})
	if err != nil {
		t.Fatal(err)
	}
	d := New(st)
	d.guard.AllowLoopback = true
	if err := d.Reload(ctx); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 12; i++ {
		d.handle(ctx, job{entry: store.Entry{}, channelID: ch.ID})
	}
	d.flushDrops()

	rows, err := st.RecentDeliveries(ctx, &ch.ID, 100)
	if err != nil {
		t.Fatal(err)
	}
	ok, dropped := 0, []store.Delivery{}
	for _, r := range rows {
		switch r.Status {
		case "ok":
			ok++
		case "dropped":
			dropped = append(dropped, r)
		}
	}
	if ok != 2 || len(dropped) != 1 {
		t.Fatalf("got %d ok and %d dropped rows, want 2 and 1", ok, len(dropped))
	}
	if want := "rate limited: 10 deliveries dropped"; dropped[0].Detail != want {
		t.Errorf("detail = %q, want %q", dropped[0].Detail, want)
	}
}

func TestShutdownAbandonsSlowDeliveries(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { <-release }))
	defer srv.Close()
	defer close(release)
	d := New(nil)
	d.guard.AllowLoopback = true
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
