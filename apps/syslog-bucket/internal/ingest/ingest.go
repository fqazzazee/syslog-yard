// Package ingest consumes newline-delimited JSON records that syslog-ng
// emits over TCP (see deploy/syslog-ng/syslog-ng.conf), normalizes them via
// the parser registry, and batch-inserts into Postgres.
//
// Durability model: a connection handler blocks on the bounded queue, and the
// batcher holds a batch while the database is unavailable (retrying with
// capped exponential backoff), so an outage turns into TCP backpressure that
// syslog-ng absorbs in its own buffers instead of silent loss here. On
// shutdown the listener and connections close first, the queue drains fully,
// and Run returns only once the batcher has flushed its last batch.
package ingest

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/syslog-yard/syslog-bucket/internal/classify"
	"github.com/syslog-yard/syslog-bucket/internal/mitre"
	"github.com/syslog-yard/syslog-bucket/internal/otmap"
	"github.com/syslog-yard/syslog-bucket/internal/parsers"
	"github.com/syslog-yard/syslog-bucket/internal/store"
)

const (
	maxLineBytes  = 1 << 20 // 1 MiB per record
	batchSize     = 500
	flushInterval = 200 * time.Millisecond
	queueDepth    = 10_000

	// connDrainGrace lets a connection read what is already buffered when
	// shutdown starts before it is cut.
	connDrainGrace = time.Second

	// DefaultDrainTimeout bounds how long shutdown waits for queued entries
	// to reach the database before giving up on them (counted as dropped).
	DefaultDrainTimeout = 6 * time.Second
)

// Insert retry backoff: doubles from retryBase up to retryMax, for as long as
// the error looks transient (or until the drain deadline at shutdown). Vars so
// tests can shorten them.
var (
	retryBase = 250 * time.Millisecond
	retryMax  = 30 * time.Second
)

// record matches the format-json template in syslog-ng.conf.
type record struct {
	Time     string `json:"time"`
	Host     string `json:"host"`
	App      string `json:"app"`
	PID      string `json:"pid"`
	MsgID    string `json:"msgid"`
	Facility string `json:"facility"`
	Severity string `json:"severity"`
	Message  string `json:"message"`
	SourceIP string `json:"source_ip"`
}

// Applier runs ingest-time rules against an entry (the rules engine).
type Applier interface {
	Apply(*store.Entry)
}

// Broadcaster receives entries right after they are inserted (the live-tail
// hub).
type Broadcaster interface {
	Broadcast([]store.Entry)
}

// Notifier delivers notifications a notify rule queued on stored entries (the
// notification dispatcher).
type Notifier interface {
	Dispatch([]store.Entry)
}

// Inserter persists a batch, filling in ids (implemented by *store.Store).
type Inserter interface {
	InsertEntries(context.Context, []store.Entry) error
}

// Stats are the ingest pipeline's counters since start.
type Stats struct {
	QueueDepth    int   `json:"queue_depth"`    // entries waiting for the batcher
	QueueCapacity int   `json:"queue_capacity"` // queue bound; full = backpressure
	Inserted      int64 `json:"inserted"`       // entries committed
	Failed        int64 `json:"failed"`         // failed insert attempts (each retry counts)
	Dropped       int64 `json:"dropped"`        // entries lost after being accepted
	BadRecords    int64 `json:"bad_records"`    // unparseable / unresolvable input records
	Retrying      bool  `json:"retrying"`       // the batcher is waiting out a database error
}

type Server struct {
	store    *store.Store
	inserter Inserter
	registry *parsers.Registry
	applier  Applier
	caster   Broadcaster
	notifier Notifier
	addr     string

	// DrainTimeout bounds the shutdown drain (DefaultDrainTimeout if zero).
	DrainTimeout time.Duration

	queue chan store.Entry

	mu      sync.Mutex
	sources map[string]int64 // "hostname|ip" -> source id

	connMu sync.Mutex
	conns  map[net.Conn]struct{}
	connWG sync.WaitGroup

	inserted, failed, dropped, badRecords atomic.Int64
	retrying                              atomic.Bool
}

func New(st *store.Store, reg *parsers.Registry, applier Applier, caster Broadcaster, notifier Notifier, addr string) *Server {
	s := &Server{
		store:    st,
		registry: reg,
		applier:  applier,
		caster:   caster,
		notifier: notifier,
		addr:     addr,
		queue:    make(chan store.Entry, queueDepth),
		sources:  make(map[string]int64),
		conns:    make(map[net.Conn]struct{}),
	}
	if st != nil {
		s.inserter = st
	}
	return s
}

// Stats snapshots the pipeline counters.
func (s *Server) Stats() Stats {
	return Stats{
		QueueDepth:    len(s.queue),
		QueueCapacity: cap(s.queue),
		Inserted:      s.inserted.Load(),
		Failed:        s.failed.Load(),
		Dropped:       s.dropped.Load(),
		BadRecords:    s.badRecords.Load(),
		Retrying:      s.retrying.Load(),
	}
}

// Run listens for syslog-ng connections until ctx is cancelled, then shuts
// down in order: stop accepting, give open connections a moment to deliver
// what is already buffered, close them, drain the queue into the database,
// and return once the batcher has exited. Database work during the drain is
// bounded by DrainTimeout.
func (s *Server) Run(ctx context.Context) error {
	ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp", s.addr)
	if err != nil {
		return err
	}
	slog.Info("ingest listening", "addr", s.addr)
	return s.serve(ctx, ln)
}

func (s *Server) serve(ctx context.Context, ln net.Listener) error {
	// dbCtx outlives ctx: it is only cancelled once the drain deadline
	// passes, so queued entries still get written during shutdown.
	dbCtx, dbCancel := context.WithCancel(context.Background())
	defer dbCancel()

	batcherDone := make(chan struct{})
	go func() {
		defer close(batcherDone)
		s.batcher(dbCtx)
	}()

	acceptDone := make(chan struct{})
	go func() {
		defer close(acceptDone)
		for {
			conn, err := ln.Accept()
			if err != nil {
				if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
					return
				}
				slog.Error("ingest accept", "error", err)
				time.Sleep(100 * time.Millisecond) // e.g. EMFILE: don't spin
				continue
			}
			s.connMu.Lock()
			s.conns[conn] = struct{}{}
			s.connWG.Add(1)
			s.connMu.Unlock()
			go s.handleConn(dbCtx, conn)
		}
	}()

	<-ctx.Done()
	slog.Info("ingest: shutting down, draining queue", "queued", len(s.queue))
	ln.Close()
	<-acceptDone

	drain := s.DrainTimeout
	if drain <= 0 {
		drain = DefaultDrainTimeout
	}
	deadline := time.AfterFunc(drain, dbCancel)
	defer deadline.Stop()

	// Cut connections after a short grace; handlers then exit, and nothing
	// else sends on the queue, so it can be closed for the batcher to drain.
	s.connMu.Lock()
	for c := range s.conns {
		c.SetReadDeadline(time.Now().Add(connDrainGrace))
	}
	s.connMu.Unlock()
	s.connWG.Wait()
	close(s.queue)
	<-batcherDone

	st := s.Stats()
	slog.Info("ingest: stopped", "inserted", st.Inserted, "dropped", st.Dropped)
	return nil
}

func (s *Server) handleConn(dbCtx context.Context, conn net.Conn) {
	defer func() {
		conn.Close()
		s.connMu.Lock()
		delete(s.conns, conn)
		s.connMu.Unlock()
		s.connWG.Done()
	}()
	slog.Info("ingest connection opened", "remote", conn.RemoteAddr())

	scanner := bufio.NewScanner(conn)
	scanner.Buffer(make([]byte, 64*1024), maxLineBytes)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var rec record
		if err := json.Unmarshal(line, &rec); err != nil {
			s.badRecords.Add(1)
			slog.Warn("ingest: bad record", "error", err)
			continue
		}
		entry, err := s.toEntry(dbCtx, rec)
		if err != nil {
			s.badRecords.Add(1)
			slog.Warn("ingest: drop record", "error", err)
			continue
		}
		// Blocking on a full queue is the point: it stops reading the
		// socket, which pushes back on syslog-ng. The queue is only closed
		// after every handler has returned, and the batcher keeps consuming
		// until then, so this can't block forever.
		s.queue <- entry
	}
	var nerr net.Error
	if err := scanner.Err(); err != nil && !(errors.As(err, &nerr) && nerr.Timeout()) && !errors.Is(err, net.ErrClosed) {
		slog.Warn("ingest connection error", "error", err)
	}
}

// clean makes device text storable: Postgres text rejects NUL bytes and
// invalid UTF-8, either of which would otherwise fail the whole batch.
func clean(s string) string {
	if strings.IndexByte(s, 0) >= 0 {
		s = strings.ReplaceAll(s, "\x00", "")
	}
	return strings.ToValidUTF8(s, "�")
}

func (s *Server) toEntry(ctx context.Context, rec record) (store.Entry, error) {
	e := store.Entry{
		ReceivedAt: time.Now().UTC(),
		Host:       clean(rec.Host),
		AppName:    clean(rec.App),
		Msg:        clean(rec.Message),
		SourceIP:   rec.SourceIP,
		Severity:   severityNum(rec.Severity),
		Status:     "new",
	}
	if f, ok := facilityNum(rec.Facility); ok {
		e.Facility = &f
	}
	if t, err := time.Parse(time.RFC3339, rec.Time); err == nil {
		e.DeviceTime = &t
	}

	meta := map[string]string{}
	if rec.PID != "" {
		meta["pid"] = clean(rec.PID)
	}
	if rec.MsgID != "" && rec.MsgID != "-" {
		meta["msgid"] = clean(rec.MsgID)
	}
	if len(meta) > 0 {
		if b, err := json.Marshal(meta); err == nil {
			e.Structured = b
		}
	}

	id, err := s.sourceID(ctx, e.Host, rec.SourceIP)
	if err != nil {
		return e, err
	}
	e.SourceID = &id

	s.registry.Apply(&e)
	// Enrich before the rule engine so rules can match on device class and
	// MITRE technique: parsers have populated structured fields by now.
	e.DeviceClass = classify.Class(e.AppName, e.Msg)
	e.Mitre = mitre.Map(&e)
	e.OT = otmap.Map(&e)
	if s.applier != nil {
		s.applier.Apply(&e)
	}
	// Live tail and webhooks see the entry as built here: serialize [] / {}
	// like the REST API, never null.
	e.Normalize()
	return e, nil
}

// sourceID memoizes sources.UpsertSource per (hostname, ip). A database
// outage is retried like an insert (blocking this connection, i.e.
// backpressure) rather than dropping the record.
func (s *Server) sourceID(ctx context.Context, hostname, ip string) (int64, error) {
	key := hostname + "|" + ip
	s.mu.Lock()
	id, ok := s.sources[key]
	s.mu.Unlock()
	if ok {
		return id, nil
	}
	err := s.retry(ctx, "upsert source", func() error {
		var err error
		id, err = s.store.UpsertSource(ctx, hostname, ip)
		return err
	})
	if err != nil {
		return 0, err
	}
	s.mu.Lock()
	s.sources[key] = id
	s.mu.Unlock()
	return id, nil
}

// retry runs op until it succeeds, fails permanently (see
// store.IsTransient), or ctx ends, backing off exponentially in between.
func (s *Server) retry(ctx context.Context, what string, op func() error) error {
	backoff := retryBase
	for attempt := 1; ; attempt++ {
		err := op()
		if err == nil {
			if attempt > 1 {
				s.retrying.Store(false)
				slog.Info("ingest: database recovered", "op", what, "attempts", attempt)
			}
			return nil
		}
		s.failed.Add(1)
		if ctx.Err() != nil || !store.IsTransient(err) {
			s.retrying.Store(false)
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
		s.retrying.Store(true)
		slog.Warn("ingest: database error, retrying", "op", what, "error", err, "attempt", attempt, "backoff", backoff)
		t := time.NewTimer(backoff)
		select {
		case <-t.C:
		case <-ctx.Done():
			t.Stop()
			return ctx.Err()
		}
		backoff = min(backoff*2, retryMax)
	}
}

// batcher drains the queue into multi-row INSERT batches until the queue is
// closed (shutdown), flushing what remains before it returns.
func (s *Server) batcher(ctx context.Context) {
	ticker := time.NewTicker(flushInterval)
	defer ticker.Stop()

	batch := make([]store.Entry, 0, batchSize)
	flush := func() {
		if len(batch) > 0 {
			s.flush(ctx, batch)
			batch = make([]store.Entry, 0, batchSize)
		}
	}
	for {
		select {
		case e, ok := <-s.queue:
			if !ok {
				flush()
				return
			}
			batch = append(batch, e)
			if len(batch) >= batchSize {
				flush()
			}
		case <-ticker.C:
			flush()
		}
	}
}

// flush stores one batch, retrying while the database is unavailable. The
// batcher doesn't read the queue meanwhile, so a long outage fills it and
// pushes back on the senders. If the server rejects the batch outright, rows
// are retried one at a time so a single bad row can't take the rest with it.
// Only committed entries are broadcast and notified.
func (s *Server) flush(ctx context.Context, batch []store.Entry) {
	stored := batch
	err := s.retry(ctx, "insert batch", func() error { return s.inserter.InsertEntries(ctx, batch) })
	if err != nil {
		if ctx.Err() != nil {
			s.dropped.Add(int64(len(batch)))
			slog.Error("ingest: drain deadline passed, dropping batch", "count", len(batch), "error", err)
			return
		}
		slog.Warn("ingest: batch rejected, inserting rows individually", "count", len(batch), "error", err)
		stored = s.insertEach(ctx, batch)
	}
	s.inserted.Add(int64(len(stored)))
	if len(stored) == 0 {
		return
	}
	if s.caster != nil {
		s.caster.Broadcast(stored)
	}
	if s.notifier != nil {
		s.notifier.Dispatch(stored)
	}
}

func (s *Server) insertEach(ctx context.Context, batch []store.Entry) []store.Entry {
	stored := batch[:0:0]
	for i := range batch {
		one := batch[i : i+1 : i+1]
		if err := s.retry(ctx, "insert entry", func() error { return s.inserter.InsertEntries(ctx, one) }); err != nil {
			s.dropped.Add(1)
			slog.Error("ingest: dropping entry the database rejected", "host", batch[i].Host, "error", err)
			continue
		}
		stored = append(stored, batch[i])
	}
	return stored
}

var severityNames = map[string]int16{
	"emerg": 0, "emergency": 0, "panic": 0,
	"alert": 1,
	"crit":  2, "critical": 2,
	"err": 3, "error": 3,
	"warning": 4, "warn": 4,
	"notice": 5,
	"info":   6, "informational": 6,
	"debug": 7,
}

func severityNum(s string) int16 {
	if n, ok := severityNames[strings.ToLower(strings.TrimSpace(s))]; ok {
		return n
	}
	return 6
}

var facilityNames = map[string]int16{
	"kern": 0, "user": 1, "mail": 2, "daemon": 3, "auth": 4, "syslog": 5,
	"lpr": 6, "news": 7, "uucp": 8, "cron": 9, "authpriv": 10, "ftp": 11,
	"ntp": 12, "security": 13, "console": 14, "solaris-cron": 15,
	"local0": 16, "local1": 17, "local2": 18, "local3": 19,
	"local4": 20, "local5": 21, "local6": 22, "local7": 23,
}

func facilityNum(s string) (int16, bool) {
	n, ok := facilityNames[strings.ToLower(strings.TrimSpace(s))]
	return n, ok
}
