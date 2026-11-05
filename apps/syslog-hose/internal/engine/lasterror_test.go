package engine

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/syslog-yard/syslog-hose/internal/preset"
)

// flakySender fails its first `fail` sends, then succeeds.
type flakySender struct {
	fail  int64
	calls atomic.Int64
}

func (f *flakySender) Send(string) error {
	if f.calls.Add(1) <= f.fail {
		return errors.New("connection to sink down, retrying in 96ms")
	}
	return nil
}
func (f *flakySender) Close() error { return nil }

// A reconnect must not leave the job flagged with an error once delivery
// is back; the failures stay counted in errors.
func TestLastErrorClearsWhenDeliveryRecovers(t *testing.T) {
	store, err := preset.NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	p, ok := store.Get("linux-host")
	if !ok {
		t.Fatal("linux-host preset missing")
	}
	cfg := JobConfig{Name: "flaky", Preset: "linux-host", Host: "127.0.0.1", Port: 1, Transport: "udp", Rate: 500, Facility: -1}
	j := &job{cfg: cfg}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	j.state = stateRunning
	j.cancel = cancel
	j.done = done
	start := time.Now()
	j.startedAt = start
	j.winStart.Store(start.UnixNano())
	j.lastError.Store("")
	s := &flakySender{fail: 5}
	activeRuns.Add(1)
	go j.run(ctx, cfg, start, s, p.NewRenderer(preset.RenderOpts{Facility: -1}), func(string, string, string) {}, done)

	deadline := time.Now().Add(3 * time.Second)
	for j.sent.Load() < 20 {
		if time.Now().After(deadline) {
			t.Fatalf("only %d sent", j.sent.Load())
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done
	st := j.status()
	if st.Errors != 5 {
		t.Errorf("errors = %d, want 5", st.Errors)
	}
	if st.LastError != "" {
		t.Errorf("lastError = %q after recovery, want empty", st.LastError)
	}
}
