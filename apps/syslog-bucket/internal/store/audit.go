package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// AuditEvent is one row of the audit log: an administrative or triage action,
// who took it, from which address, and whether it succeeded. Summary is a
// small JSON object describing the change; it never carries secrets.
type AuditEvent struct {
	ID         int64           `json:"id"`
	Time       time.Time       `json:"time"`
	ActorID    *int64          `json:"actor_id"`
	ActorName  string          `json:"actor"`
	ActorIP    string          `json:"ip"`
	Action     string          `json:"action"`
	TargetType string          `json:"target_type"`
	TargetID   string          `json:"target_id"`
	Summary    json.RawMessage `json:"summary"`
	Success    bool            `json:"success"`
}

// InsertAudit writes a batch of audit events in one round trip. A zero Time
// means "now".
func (s *Store) InsertAudit(ctx context.Context, events []AuditEvent) error {
	if len(events) == 0 {
		return nil
	}
	b := &pgx.Batch{}
	for _, e := range events {
		at := e.Time
		if at.IsZero() {
			at = time.Now()
		}
		summary := e.Summary
		if len(summary) == 0 {
			summary = json.RawMessage(`{}`)
		}
		b.Queue(`INSERT INTO audit_log
			(at, actor_id, actor_name, actor_ip, action, target_type, target_id, summary, success)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
			at, e.ActorID, e.ActorName, e.ActorIP, e.Action, e.TargetType, e.TargetID, []byte(summary), e.Success)
	}
	return s.Pool.SendBatch(ctx, b).Close()
}

// AuditCursor is a position in the newest-first audit listing: the (time,
// id) of the last row of the previous page.
type AuditCursor struct {
	Time time.Time
	ID   int64
}

// String encodes the cursor for an API response: microseconds since the
// epoch (Postgres' timestamp precision) and the row id.
func (c AuditCursor) String() string {
	return strconv.FormatInt(c.Time.UnixMicro(), 10) + "-" + strconv.FormatInt(c.ID, 10)
}

// ParseAuditCursor decodes AuditCursor.String.
func ParseAuditCursor(s string) (AuditCursor, error) {
	i := strings.LastIndexByte(s, '-')
	if i <= 0 {
		return AuditCursor{}, errors.New("malformed cursor")
	}
	us, id := s[:i], s[i+1:]
	micros, err1 := strconv.ParseInt(us, 10, 64)
	n, err2 := strconv.ParseInt(id, 10, 64)
	if err1 != nil || err2 != nil {
		return AuditCursor{}, errors.New("malformed cursor")
	}
	return AuditCursor{Time: time.UnixMicro(micros), ID: n}, nil
}

// AuditFilter narrows an audit listing. Zero fields don't filter.
type AuditFilter struct {
	Actor      string // username snapshot, case-insensitive exact match
	ActorID    *int64
	Action     string
	TargetType string
	TargetID   string
	Success    *bool
	Since      *time.Time // inclusive
	Until      *time.Time // exclusive
	Before     *AuditCursor
	Limit      int
}

const (
	defaultAuditLimit = 100
	maxAuditLimit     = 500
)

// ListAudit returns audit events newest first. When the page is full, next
// is the cursor for the following page; otherwise it is nil.
func (s *Store) ListAudit(ctx context.Context, f AuditFilter) (events []AuditEvent, next *AuditCursor, err error) {
	var where []string
	var args []any
	arg := func(v any) string {
		args = append(args, v)
		return "$" + strconv.Itoa(len(args))
	}
	if f.Actor != "" {
		where = append(where, "lower(actor_name) = lower("+arg(f.Actor)+")")
	}
	if f.ActorID != nil {
		where = append(where, "actor_id = "+arg(*f.ActorID))
	}
	if f.Action != "" {
		where = append(where, "action = "+arg(f.Action))
	}
	if f.TargetType != "" {
		where = append(where, "target_type = "+arg(f.TargetType))
	}
	if f.TargetID != "" {
		where = append(where, "target_id = "+arg(f.TargetID))
	}
	if f.Success != nil {
		where = append(where, "success = "+arg(*f.Success))
	}
	if f.Since != nil {
		where = append(where, "at >= "+arg(*f.Since))
	}
	if f.Until != nil {
		where = append(where, "at < "+arg(*f.Until))
	}
	if f.Before != nil {
		where = append(where, fmt.Sprintf("(at, id) < (%s, %s)", arg(f.Before.Time), arg(f.Before.ID)))
	}
	limit := f.Limit
	if limit <= 0 {
		limit = defaultAuditLimit
	}
	if limit > maxAuditLimit {
		limit = maxAuditLimit
	}
	q := `SELECT id, at, actor_id, actor_name, actor_ip, action, target_type, target_id, summary, success
		FROM audit_log`
	if len(where) > 0 {
		q += " WHERE " + strings.Join(where, " AND ")
	}
	q += " ORDER BY at DESC, id DESC LIMIT " + arg(limit)

	rows, err := s.Pool.Query(ctx, q, args...)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	events = []AuditEvent{}
	for rows.Next() {
		var e AuditEvent
		var summary []byte
		if err := rows.Scan(&e.ID, &e.Time, &e.ActorID, &e.ActorName, &e.ActorIP, &e.Action,
			&e.TargetType, &e.TargetID, &summary, &e.Success); err != nil {
			return nil, nil, err
		}
		e.Summary = summary
		events = append(events, e)
	}
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}
	if len(events) == limit {
		last := events[len(events)-1]
		next = &AuditCursor{Time: last.Time, ID: last.ID}
	}
	return events, next, nil
}

// PruneAudit deletes audit rows older than the cutoff and reports how many
// went.
func (s *Store) PruneAudit(ctx context.Context, olderThan time.Duration) (int64, error) {
	tag, err := s.Pool.Exec(ctx,
		`DELETE FROM audit_log WHERE at < now() - make_interval(secs => $1)`, olderThan.Seconds())
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}
