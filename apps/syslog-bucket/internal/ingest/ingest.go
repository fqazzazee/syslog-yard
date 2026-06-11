// Package ingest consumes newline-delimited JSON records that syslog-ng
// emits over TCP (see deploy/syslog-ng/syslog-ng.conf), normalizes them via
// the parser registry, and batch-inserts into Postgres.
package ingest

import (
	"bufio"
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/syslog-yard/syslog-bucket/internal/classify"
	"github.com/syslog-yard/syslog-bucket/internal/mitre"
	"github.com/syslog-yard/syslog-bucket/internal/parsers"
	"github.com/syslog-yard/syslog-bucket/internal/store"
)

const (
	maxLineBytes  = 1 << 20 // 1 MiB per record
	batchSize     = 500
	flushInterval = 200 * time.Millisecond
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

type Server struct {
	store    *store.Store
	registry *parsers.Registry
	applier  Applier
	caster   Broadcaster
	notifier Notifier
	addr     string

	queue chan store.Entry

	mu      sync.Mutex
	sources map[string]int64 // "hostname|ip" -> source id
}

func New(st *store.Store, reg *parsers.Registry, applier Applier, caster Broadcaster, notifier Notifier, addr string) *Server {
	return &Server{
		store:    st,
		registry: reg,
		applier:  applier,
		caster:   caster,
		notifier: notifier,
		addr:     addr,
		queue:    make(chan store.Entry, 10_000),
		sources:  make(map[string]int64),
	}
}

// Run listens for syslog-ng connections until ctx is cancelled.
func (s *Server) Run(ctx context.Context) error {
	ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp", s.addr)
	if err != nil {
		return err
	}
	slog.Info("ingest listening", "addr", s.addr)

	go s.batcher(ctx)
	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			slog.Error("ingest accept", "error", err)
			continue
		}
		go s.handleConn(ctx, conn)
	}
}

func (s *Server) handleConn(ctx context.Context, conn net.Conn) {
	defer conn.Close()
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
			slog.Warn("ingest: bad record", "error", err)
			continue
		}
		entry, err := s.toEntry(ctx, rec)
		if err != nil {
			slog.Warn("ingest: drop record", "error", err)
			continue
		}
		select {
		case s.queue <- entry:
		case <-ctx.Done():
			return
		}
	}
	if err := scanner.Err(); err != nil && ctx.Err() == nil {
		slog.Warn("ingest connection error", "error", err)
	}
}

func (s *Server) toEntry(ctx context.Context, rec record) (store.Entry, error) {
	e := store.Entry{
		ReceivedAt: time.Now().UTC(),
		Host:       rec.Host,
		AppName:    rec.App,
		Msg:        rec.Message,
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
		meta["pid"] = rec.PID
	}
	if rec.MsgID != "" && rec.MsgID != "-" {
		meta["msgid"] = rec.MsgID
	}
	if len(meta) > 0 {
		if b, err := json.Marshal(meta); err == nil {
			e.Structured = b
		}
	}

	id, err := s.sourceID(ctx, rec.Host, rec.SourceIP)
	if err != nil {
		return e, err
	}
	e.SourceID = &id

	s.registry.Apply(&e)
	// Enrich before the rule engine so rules can match on device class and
	// MITRE technique (S8): parsers have populated structured fields by now.
	e.DeviceClass = classify.Class(e.AppName, e.Msg)
	e.Mitre = mitre.Map(&e)
	if s.applier != nil {
		s.applier.Apply(&e)
	}
	return e, nil
}

// sourceID memoizes sources.UpsertSource per (hostname, ip).
func (s *Server) sourceID(ctx context.Context, hostname, ip string) (int64, error) {
	key := hostname + "|" + ip
	s.mu.Lock()
	id, ok := s.sources[key]
	s.mu.Unlock()
	if ok {
		return id, nil
	}
	id, err := s.store.UpsertSource(ctx, hostname, ip)
	if err != nil {
		return 0, err
	}
	s.mu.Lock()
	s.sources[key] = id
	s.mu.Unlock()
	return id, nil
}

// batcher drains the queue into COPY batches.
func (s *Server) batcher(ctx context.Context) {
	ticker := time.NewTicker(flushInterval)
	defer ticker.Stop()

	batch := make([]store.Entry, 0, batchSize)
	flush := func() {
		if len(batch) == 0 {
			return
		}
		if err := s.store.InsertEntries(context.WithoutCancel(ctx), batch); err != nil {
			slog.Error("ingest: insert batch", "error", err, "count", len(batch))
		} else {
			if s.caster != nil {
				s.caster.Broadcast(batch)
			}
			if s.notifier != nil {
				s.notifier.Dispatch(batch)
			}
		}
		batch = batch[:0]
	}

	for {
		select {
		case e := <-s.queue:
			batch = append(batch, e)
			if len(batch) >= batchSize {
				flush()
			}
		case <-ticker.C:
			flush()
		case <-ctx.Done():
			flush()
			return
		}
	}
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
