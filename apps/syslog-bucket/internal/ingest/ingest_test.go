package ingest

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/syslog-yard/syslog-bucket/internal/parsers"
	"github.com/syslog-yard/syslog-bucket/internal/store"
	"github.com/syslog-yard/syslog-bucket/internal/store/storetest"
)

func init() {
	retryBase = 5 * time.Millisecond
	retryMax = 20 * time.Millisecond
}

// fakeInserter records committed entries; fail decides per call whether to
// fail (and with what).
type fakeInserter struct {
	mu     sync.Mutex
	stored []store.Entry
	calls  int
	delay  time.Duration
	fail   func(call int, batch []store.Entry) error
}

func (f *fakeInserter) InsertEntries(ctx context.Context, batch []store.Entry) error {
	f.mu.Lock()
	f.calls++
	call := f.calls
	f.mu.Unlock()
	if f.delay > 0 {
		time.Sleep(f.delay)
	}
	if f.fail != nil {
		if err := f.fail(call, batch); err != nil {
			return err
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := range batch {
		batch[i].ID = int64(len(f.stored) + 1)
		f.stored = append(f.stored, batch[i])
	}
	return nil
}

func (f *fakeInserter) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.stored)
}

type countCaster struct {
	mu sync.Mutex
	n  int
}

func (c *countCaster) Broadcast(es []store.Entry) {
	c.mu.Lock()
	c.n += len(es)
	c.mu.Unlock()
}

func testServer(ins Inserter) (*Server, *countCaster) {
	cc := &countCaster{}
	s := New(nil, parsers.NewRegistry(parsers.Generic{}), nil, cc, nil, "")
	s.inserter = ins
	return s, cc
}

func runServe(t *testing.T, s *Server) (cancel func(), done <-chan error) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s.addr = ln.Addr().String()
	ctx, cancelFn := context.WithCancel(context.Background())
	ch := make(chan error, 1)
	go func() { ch <- s.serve(ctx, ln) }()
	return cancelFn, ch
}

func waitDone(t *testing.T, done <-chan error, within time.Duration) {
	t.Helper()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("serve: %v", err)
		}
	case <-time.After(within):
		t.Fatalf("serve did not return within %v", within)
	}
}

// Everything queued when shutdown starts reaches the store before Run
// returns — not just the batch in hand.
func TestShutdownDrainsQueue(t *testing.T) {
	ins := &fakeInserter{delay: 2 * time.Millisecond}
	s, cc := testServer(ins)
	cancel, done := runServe(t, s)
	const n = 3*batchSize + 17
	for i := 0; i < n; i++ {
		s.queue <- store.Entry{Msg: fmt.Sprint(i)}
	}
	cancel()
	waitDone(t, done, 5*time.Second)
	if got := ins.count(); got != n {
		t.Fatalf("stored %d of %d queued entries", got, n)
	}
	if st := s.Stats(); st.Inserted != n || st.Dropped != 0 || st.QueueDepth != 0 {
		t.Errorf("stats = %+v", st)
	}
	if cc.n != n {
		t.Errorf("broadcast %d, want %d", cc.n, n)
	}
}

// A transient failure holds the batch and retries; nothing is lost.
func TestFlushRetriesTransientErrors(t *testing.T) {
	ins := &fakeInserter{fail: func(call int, _ []store.Entry) error {
		if call <= 3 {
			return errors.New("dial tcp: connection refused")
		}
		return nil
	}}
	s, cc := testServer(ins)
	s.flush(context.Background(), []store.Entry{{Msg: "a"}, {Msg: "b"}})
	if ins.count() != 2 || cc.n != 2 {
		t.Fatalf("stored %d broadcast %d", ins.count(), cc.n)
	}
	if st := s.Stats(); st.Failed != 3 || st.Inserted != 2 || st.Retrying {
		t.Errorf("stats = %+v", st)
	}
}

// A batch the server rejects is retried row by row so only the bad row is
// lost, and only stored rows are broadcast.
func TestFlushIsolatesRejectedRows(t *testing.T) {
	ins := &fakeInserter{fail: func(_ int, batch []store.Entry) error {
		for _, e := range batch {
			if e.Msg == "bad" {
				return &pgconn.PgError{Code: "23503", Message: "fk"}
			}
		}
		return nil
	}}
	s, cc := testServer(ins)
	s.flush(context.Background(), []store.Entry{{Msg: "a"}, {Msg: "bad"}, {Msg: "c"}})
	if ins.count() != 2 || cc.n != 2 {
		t.Fatalf("stored %d broadcast %d, want 2/2", ins.count(), cc.n)
	}
	if st := s.Stats(); st.Dropped != 1 || st.Inserted != 2 {
		t.Errorf("stats = %+v", st)
	}
}

// With the database down for good, shutdown still finishes within the drain
// timeout and accounts for what it couldn't store.
func TestShutdownDrainDeadline(t *testing.T) {
	ins := &fakeInserter{fail: func(int, []store.Entry) error { return errors.New("connection reset") }}
	s, _ := testServer(ins)
	s.DrainTimeout = 200 * time.Millisecond
	cancel, done := runServe(t, s)
	for i := 0; i < 10; i++ {
		s.queue <- store.Entry{Msg: "x"}
	}
	time.Sleep(50 * time.Millisecond) // let the batcher pick them up and start retrying
	cancel()
	waitDone(t, done, 3*time.Second)
	if st := s.Stats(); st.Dropped != 10 || st.Inserted != 0 {
		t.Errorf("stats = %+v", st)
	}
}

// Live-tail / webhook payloads carry source_ip and [] / {} rather than null.
func TestToEntryNormalizes(t *testing.T) {
	s, _ := testServer(&fakeInserter{})
	s.sources["fw1|10.1.2.3"] = 42 // skip the database lookup
	e, err := s.toEntry(context.Background(), record{Host: "fw1", SourceIP: "10.1.2.3", Message: "hello\x00 world", Severity: "err"})
	if err != nil {
		t.Fatal(err)
	}
	if e.SourceIP != "10.1.2.3" || e.SourceID == nil || *e.SourceID != 42 {
		t.Errorf("source = %q / %v", e.SourceIP, e.SourceID)
	}
	if strings.ContainsRune(e.Msg, 0) {
		t.Errorf("NUL byte kept in msg %q", e.Msg)
	}
	b, _ := json.Marshal(&e)
	for _, null := range []string{`"mitre":null`, `"ot":null`, `"tag_ids":null`, `"structured":null`} {
		if strings.Contains(string(b), null) {
			t.Errorf("payload has %s: %s", null, b)
		}
	}
	if !strings.Contains(string(b), `"source_ip":"10.1.2.3"`) {
		t.Errorf("payload lacks source_ip: %s", b)
	}
}

// End to end against Postgres: records written over TCP right before
// shutdown are all committed by the time Run returns.
func TestShutdownCommitsInFlightRecordsPG(t *testing.T) {
	st := storetest.New(t)
	s := New(st, parsers.NewRegistry(parsers.Generic{}), nil, nil, nil, "")
	cancel, done := runServe(t, s)

	conn, err := net.Dial("tcp", s.addr)
	if err != nil {
		t.Fatal(err)
	}
	const n = 2000
	var sb strings.Builder
	for i := 0; i < n; i++ {
		fmt.Fprintf(&sb, `{"host":"h%d","app":"a","severity":"info","message":"m %d","source_ip":"10.0.0.%d"}`+"\n", i%3, i, i%3)
	}
	if _, err := conn.Write([]byte(sb.String())); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	cancel()
	waitDone(t, done, 10*time.Second)
	conn.Close()

	var got int
	if err := st.Pool.QueryRow(context.Background(), `SELECT count(*) FROM entries`).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != n {
		t.Errorf("committed %d of %d records", got, n)
	}
}
