package audit

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/syslog-yard/syslog-bucket/internal/store"
)

// fakeWriter collects inserted events; block holds every insert until
// closed, and fail makes inserts error.
type fakeWriter struct {
	mu     sync.Mutex
	rows   []store.AuditEvent
	block  chan struct{}
	fail   bool
	prunes int
}

func (f *fakeWriter) InsertAudit(ctx context.Context, events []store.AuditEvent) error {
	if f.block != nil {
		select {
		case <-f.block:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail {
		return errors.New("database down")
	}
	f.rows = append(f.rows, events...)
	return nil
}

func (f *fakeWriter) PruneAudit(context.Context, time.Duration) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.prunes++
	return 0, nil
}

func (f *fakeWriter) snapshot() []store.AuditEvent {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]store.AuditEvent(nil), f.rows...)
}

func TestRecordWritesOnShutdown(t *testing.T) {
	w := &fakeWriter{}
	r := New(w, 0)
	u := &store.User{ID: 4, Username: "ana"}
	r.Record(Event{Action: RuleCreate, TargetType: "rule", TargetID: "9", Success: true,
		Summary: map[string]any{"name": "ssh brute force"}}.As(u))
	r.Record(Event{ActorName: "mallory", Action: SignIn})
	r.Shutdown(5 * time.Second)

	rows := w.snapshot()
	if len(rows) != 2 {
		t.Fatalf("wrote %d rows, want 2", len(rows))
	}
	got := rows[0]
	if got.ActorID == nil || *got.ActorID != 4 || got.ActorName != "ana" || got.Action != RuleCreate ||
		string(got.Summary) != `{"name":"ssh brute force"}` || !got.Success || got.Time.IsZero() {
		t.Errorf("row = %+v (summary %s)", got, got.Summary)
	}
	if rows[1].ActorID != nil || rows[1].Success || len(rows[1].Summary) != 0 {
		t.Errorf("failed sign-in row = %+v", rows[1])
	}

	// After shutdown, recording is a harmless no-op.
	r.Record(Event{Action: RuleDelete})
	if len(w.snapshot()) != 2 {
		t.Error("an event recorded after shutdown was written")
	}
}

// A stuck or failing database must never hold up the caller.
func TestRecordNeverBlocks(t *testing.T) {
	// Every lost event is logged; keep the test output readable.
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })

	w := &fakeWriter{block: make(chan struct{})}
	r := New(w, 0)
	done := make(chan struct{})
	go func() {
		for range queueSize + maxBatch + 100 { // more than the queue holds
			r.Record(Event{Action: EntryUpdate, Success: true})
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Record blocked behind a stuck writer")
	}
	w.mu.Lock()
	w.fail = true
	w.mu.Unlock()
	close(w.block)
	r.Shutdown(5 * time.Second)
	if n := len(w.snapshot()); n != 0 {
		t.Errorf("failing writer stored %d rows", n)
	}
}

func TestNilRecorderIsSafe(t *testing.T) {
	var r *Recorder
	r.Record(Event{Action: SignIn})
	r.Shutdown(time.Second)
	r.Run(context.Background()) // returns at once
}

func TestRunPrunesOnlyWithRetention(t *testing.T) {
	w := &fakeWriter{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	New(w, 0).Run(ctx)
	if w.prunes != 0 {
		t.Errorf("retention 0 pruned %d times", w.prunes)
	}
	New(w, time.Hour).Run(ctx)
	if w.prunes != 1 {
		t.Errorf("pruned %d times at start, want 1", w.prunes)
	}
}

func TestActorNameIsCapped(t *testing.T) {
	w := &fakeWriter{}
	r := New(w, 0)
	r.Record(Event{ActorName: strings.Repeat("é", 200), Action: SignIn})
	r.Shutdown(5 * time.Second)
	name := w.snapshot()[0].ActorName
	if len(name) > maxNameLen || !strings.HasPrefix(strings.Repeat("é", 200), name) {
		t.Errorf("capped name is %d bytes / not a rune-aligned prefix", len(name))
	}
}
