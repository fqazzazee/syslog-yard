package notify

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"unicode/utf8"

	"github.com/syslog-yard/syslog-bucket/internal/store"
)

func TestLimiter(t *testing.T) {
	l := newLimiter()
	if !l.allow(2) || !l.allow(2) {
		t.Fatal("first two should be allowed")
	}
	if l.allow(2) {
		t.Fatal("third should be rate limited")
	}
	if !l.allow(0) {
		t.Fatal("rate 0 means unlimited")
	}
}

func TestDeliverWebhookAndSlack(t *testing.T) {
	var gotBody []byte
	var gotCT string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotBody, _ = io.ReadAll(r.Body)
		gotCT = r.Header.Get("Content-Type")
		w.WriteHeader(200)
	}))
	defer srv.Close()

	d := New(nil)          // deliver doesn't touch the store
	d.allowLoopback = true // httptest listens on 127.0.0.1
	e := store.Entry{Severity: 2, Host: "fw1", AppName: "fortigate", Msg: "boom", Mitre: []string{"T1190"}}

	// Generic webhook: full entry payload.
	ch := store.Channel{Kind: "webhook", Config: json.RawMessage(`{"url":"` + srv.URL + `"}`)}
	if err := d.deliver(context.Background(), ch, e, summary(e)); err != nil {
		t.Fatalf("webhook deliver: %v", err)
	}
	if gotCT != "application/json" {
		t.Errorf("content-type = %q", gotCT)
	}
	var payload struct {
		Text  string      `json:"text"`
		Entry store.Entry `json:"entry"`
	}
	if err := json.Unmarshal(gotBody, &payload); err != nil {
		t.Fatalf("payload: %v", err)
	}
	if payload.Entry.Host != "fw1" || payload.Text == "" {
		t.Errorf("unexpected webhook payload: %s", gotBody)
	}

	// Slack/Teams: {"text": ...} only.
	ch.Kind = "slack"
	if err := d.deliver(context.Background(), ch, e, summary(e)); err != nil {
		t.Fatalf("slack deliver: %v", err)
	}
	var chat map[string]any
	if err := json.Unmarshal(gotBody, &chat); err != nil || chat["text"] == "" {
		t.Errorf("slack payload missing text: %s", gotBody)
	}
	if _, hasEntry := chat["entry"]; hasEntry {
		t.Errorf("slack payload should not include the full entry: %s", gotBody)
	}
}

func TestDeliverWebhookError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "nope", http.StatusInternalServerError)
	}))
	defer srv.Close()
	d := New(nil)
	d.allowLoopback = true
	ch := store.Channel{Kind: "slack", Config: json.RawMessage(`{"url":"` + srv.URL + `"}`)}
	if err := d.deliver(context.Background(), ch, store.Entry{}, "x"); err == nil {
		t.Fatal("expected error on 500 response")
	}
}

// A burst of deliveries for a channel the dispatcher has no limiter for yet
// must share one limiter (no concurrent map write, no rate-limit bypass).
// Run with -race.
func TestHandleBurstNewChannelSharesLimiter(t *testing.T) {
	var mu sync.Mutex
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		hits++
		mu.Unlock()
	}))
	defer srv.Close()

	d := New(nil)
	d.allowLoopback = true
	const rate = 5
	d.mu.Lock()
	d.channels[1] = store.Channel{ID: 1, Kind: "slack", Enabled: true, RatePerMin: rate,
		Config: json.RawMessage(`{"url":"` + srv.URL + `"}`)}
	d.mu.Unlock()

	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			d.handle(context.Background(), job{entry: store.Entry{ID: int64(i)}, channelID: 1})
		}(i)
	}
	wg.Wait()
	if hits != rate {
		t.Errorf("delivered %d, want exactly %d (one shared limiter)", hits, rate)
	}
}

// Queue-full drops are counted in memory, not logged one INSERT at a time.
func TestDispatchQueueFullCountsDrops(t *testing.T) {
	d := New(nil)
	d.queue = make(chan job, 1)
	e := store.Entry{ID: 1, Notifies: []store.Notify{{ChannelID: 3, RuleID: 9}}}
	d.Dispatch([]store.Entry{e, e, e})
	d.dropMu.Lock()
	got := d.drops[dropKey{3, 9}]
	d.dropMu.Unlock()
	if got != 2 {
		t.Fatalf("drops = %d, want 2", got)
	}
	d.flushDrops()
	if len(d.drops) != 0 {
		t.Errorf("flush should reset counters: %v", d.drops)
	}
}

func TestTruncateRunesKeepsUTF8Valid(t *testing.T) {
	s := strings.Repeat("a", 299) + "é" + "tail"
	got := truncateRunes(s, 300)
	if !utf8.ValidString(got) {
		t.Fatalf("truncated string is not valid UTF-8: %q", got)
	}
	if got != strings.Repeat("a", 299)+"…" {
		t.Errorf("got %q", got)
	}
	if truncateRunes("short", 300) != "short" {
		t.Error("short strings must be unchanged")
	}
}

func TestSummaryIncludesMitre(t *testing.T) {
	s := summary(store.Entry{Severity: 3, Host: "h", AppName: "a", Msg: "m", Mitre: []string{"T1110"}})
	if want := "MITRE T1110"; !contains(s, want) {
		t.Errorf("summary %q missing %q", s, want)
	}
}

func contains(s, sub string) bool { return len(s) >= len(sub) && (indexOf(s, sub) >= 0) }
func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
