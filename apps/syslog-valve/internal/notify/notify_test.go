package notify

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/syslog-yard/shared/netguard"
	"github.com/syslog-yard/syslog-valve/internal/graph"
)

func notifyGraph(url string, rate int, kind string) *graph.Graph {
	return &graph.Graph{Nodes: []graph.Node{{
		ID: "notify-1", Type: graph.TypeNotify, Name: "page",
		Config: graph.Config{NotifyKind: kind, URL: url, RatePerMin: rate},
	}}}
}

const ident = "notify_1"

func datagram(msg string) string {
	return ident + "\t2026-01-01T00:00:00Z\thost1\tsshd\terr\t" + msg + "\n"
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// A webhook that never answers must not stall the socket reader: handle
// returns at once and overflow is counted, not logged per message.
func TestHandleNeverBlocksOnDeadWebhook(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
	}))
	defer srv.Close()
	defer close(release)

	d := newDispatcher(true)
	d.SetGraph(notifyGraph(srv.URL, 100000, "webhook"))
	defer d.SetGraph(&graph.Graph{})

	start := time.Now()
	for i := 0; i < 1000; i++ {
		d.handle(datagram("boom"))
	}
	if el := time.Since(start); el > time.Second {
		t.Fatalf("1000 handle calls took %v with a dead webhook", el)
	}
	st := d.Stats()[ident]
	// One in flight, queueSize waiting, the rest dropped.
	if st.Dropped < 1000-queueSize-1 {
		t.Fatalf("dropped = %d, want >= %d", st.Dropped, 1000-queueSize-1)
	}
	// At most one summary entry (if the worker dequeued after drops began).
	if n := len(d.Recent()); n > 1 {
		t.Fatalf("drops recorded individually in the log ring: %d entries", n)
	}
}

func TestDefaultRateLimit(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
	}))
	defer srv.Close()

	d := newDispatcher(true)
	d.SetGraph(notifyGraph(srv.URL, 0, "webhook")) // unset -> default
	defer d.SetGraph(&graph.Graph{})
	if got := d.Stats()[ident].RatePerMin; got != DefaultRatePerMin {
		t.Fatalf("rate = %d, want default %d", got, DefaultRatePerMin)
	}
	for i := 0; i < DefaultRatePerMin+40; i++ {
		d.handle(datagram("x"))
		if i%16 == 15 {
			// let the worker drain so only the limiter drops
			waitFor(t, "queue drain", func() bool { return hits.Load() >= int64(min(i+1, DefaultRatePerMin)) })
		}
	}
	waitFor(t, "deliveries", func() bool { return hits.Load() == DefaultRatePerMin })
	if st := d.Stats()[ident]; st.Dropped != 40 || st.Sent != DefaultRatePerMin {
		t.Fatalf("stats = %+v, want 40 dropped, %d sent", st, DefaultRatePerMin)
	}
	// Drops are summarized in the log ring at the next delivery, not
	// recorded one by one.
	d.mu.Lock()
	d.targets[ident].lim = newLimiter()
	d.mu.Unlock()
	d.handle(datagram("after"))
	waitFor(t, "summary", func() bool {
		total, entries := 0, 0
		for _, dl := range d.Recent() {
			if dl.Status == "dropped" {
				var n int
				fmt.Sscanf(dl.Detail, "%d message(s)", &n)
				total += n
				entries++
			}
		}
		return total == 40 && entries <= 2
	})
}

func TestNoRedirectsAndNoBodyEcho(t *testing.T) {
	var followed atomic.Bool
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		followed.Store(true)
	}))
	defer target.Close()
	redir := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer redir.Close()
	secret := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		io.WriteString(w, "SECRET-INTERNAL-DATA")
	}))
	defer secret.Close()

	d := newDispatcher(true)
	err := d.TestSend(context.Background(), "webhook", redir.URL)
	if err == nil || !strings.Contains(err.Error(), "307") {
		t.Fatalf("redirect: err = %v, want HTTP 307 reported", err)
	}
	if followed.Load() {
		t.Fatal("redirect was followed")
	}
	err = d.TestSend(context.Background(), "webhook", secret.URL)
	if err == nil || strings.Contains(err.Error(), "SECRET") {
		t.Fatalf("error echoes the response body: %v", err)
	}
}

func TestDialGuard(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	d := New() // production policy: loopback refused
	err := d.TestSend(context.Background(), "webhook", srv.URL)
	if err == nil || !strings.Contains(err.Error(), "loopback") {
		t.Fatalf("loopback: err = %v", err)
	}
	if strings.Contains(err.Error(), srv.URL) {
		t.Errorf("error repeats the URL: %v", err)
	}
	// The address table itself is tested in apps/shared/netguard.
	if !errors.Is(err, netguard.ErrBlocked) {
		t.Errorf("err = %v, want netguard.ErrBlocked", err)
	}
}

func TestSlackEscaping(t *testing.T) {
	var body atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, _ := io.ReadAll(r.Body)
		body.Store(string(data))
	}))
	defer srv.Close()
	d := newDispatcher(true)
	d.SetGraph(notifyGraph(srv.URL, 10, "slack"))
	defer d.SetGraph(&graph.Graph{})
	d.handle(datagram("<!channel> ping & <https://evil|click>"))
	waitFor(t, "delivery", func() bool { return body.Load() != nil })
	var got struct{ Text string }
	if err := json.Unmarshal([]byte(body.Load().(string)), &got); err != nil {
		t.Fatal(err)
	}
	if strings.ContainsAny(got.Text, "<>") || !strings.Contains(got.Text, "&lt;!channel&gt; ping &amp; &lt;https://evil|click&gt;") {
		t.Fatalf("slack text not escaped: %q", got.Text)
	}
}

func TestSetGraphStopsRemovedWorkers(t *testing.T) {
	d := newDispatcher(true)
	d.SetGraph(notifyGraph("http://10.0.0.1/", 5, "webhook"))
	d.mu.Lock()
	quit := d.targets[ident].quit
	d.mu.Unlock()
	d.SetGraph(notifyGraph("http://10.0.0.2/", 7, "webhook")) // same node, new config
	if got := d.Targets(); len(got) != 1 || d.Stats()[ident].RatePerMin != 7 {
		t.Fatalf("targets = %v stats = %+v", got, d.Stats())
	}
	select {
	case <-quit:
		t.Fatal("worker of a kept node was stopped")
	default:
	}
	d.SetGraph(&graph.Graph{})
	select {
	case <-quit:
	default:
		t.Fatal("worker of a removed node still running")
	}
}
