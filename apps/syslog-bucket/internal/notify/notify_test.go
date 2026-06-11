package notify

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

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

	d := New(nil) // deliver doesn't touch the store
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
	ch := store.Channel{Kind: "slack", Config: json.RawMessage(`{"url":"` + srv.URL + `"}`)}
	if err := d.deliver(context.Background(), ch, store.Entry{}, "x"); err == nil {
		t.Fatal("expected error on 500 response")
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
