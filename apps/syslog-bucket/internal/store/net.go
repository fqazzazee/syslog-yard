package store

import (
	"context"
	"time"
)

// NetScanRow is the slim projection the network view classifies: just enough
// to extract IP addresses, newest first. Classification happens at read time
// (internal/netclass), so threat-feed updates flag old entries too.
type NetScanRow struct {
	ID         int64
	ReceivedAt time.Time
	Host       string
	Msg        string
}

// NetScan returns up to limit non-suppressed entries received since the
// given time, newest first.
func (s *Store) NetScan(ctx context.Context, since time.Time, limit int) ([]NetScanRow, error) {
	rows, err := s.Pool.Query(ctx, `
		SELECT id, received_at, host, msg FROM entries
		WHERE received_at >= $1 AND NOT suppressed
		ORDER BY id DESC LIMIT $2`, since, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []NetScanRow{}
	for rows.Next() {
		var r NetScanRow
		if err := rows.Scan(&r.ID, &r.ReceivedAt, &r.Host, &r.Msg); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// EntriesByIDs fetches full entries for the given ids, newest first. Used by
// the network view's drill-down, where the matching ids come from a read-time
// classification pass rather than a SQL condition.
func (s *Store) EntriesByIDs(ctx context.Context, ids []int64) ([]Entry, error) {
	if len(ids) == 0 {
		return []Entry{}, nil
	}
	rows, err := s.Pool.Query(ctx, `
		SELECT e.id, e.received_at, e.device_time, e.source_id, COALESCE(s.ip, ''),
		       e.facility, e.severity, e.app_name, e.host, e.msg, e.structured, e.priority, e.status, e.suppressed,
		       e.device_class, e.mitre, e.ot,
		       COALESCE((SELECT array_agg(et.tag_id ORDER BY et.tag_id) FROM entry_tags et WHERE et.entry_id = e.id), '{}')
		FROM entries e LEFT JOIN sources s ON s.id = e.source_id
		WHERE e.id = ANY($1) ORDER BY e.id DESC`, ids)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	entries := []Entry{}
	for rows.Next() {
		var e Entry
		if err := rows.Scan(&e.ID, &e.ReceivedAt, &e.DeviceTime, &e.SourceID, &e.SourceIP,
			&e.Facility, &e.Severity, &e.AppName, &e.Host, &e.Msg, &e.Structured, &e.Priority, &e.Status,
			&e.Suppressed, &e.DeviceClass, &e.Mitre, &e.OT, &e.TagIDs); err != nil {
			return nil, err
		}
		entries = append(entries, e)
	}
	return entries, rows.Err()
}
