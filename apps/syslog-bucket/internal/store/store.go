// Package store is the PostgreSQL persistence layer. It is the only package
// that talks to the database; the interface is kept narrow so an alternative
// entries backend (e.g. ClickHouse) can be slotted in later.
package store

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/syslog-yard/syslog-bucket/internal/rules"
)

type Store struct {
	Pool *pgxpool.Pool
}

// Open connects to Postgres, retrying for up to a minute so the app can start
// alongside the database container.
func Open(ctx context.Context, url string) (*Store, error) {
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		return nil, fmt.Errorf("parse database url: %w", err)
	}
	deadline := time.Now().Add(60 * time.Second)
	for {
		pool, err := pgxpool.NewWithConfig(ctx, cfg)
		if err == nil {
			if err = pool.Ping(ctx); err == nil {
				return &Store{Pool: pool}, nil
			}
			pool.Close()
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("connect to database: %w", err)
		}
		slog.Info("database not ready, retrying", "error", err)
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
}

func (s *Store) Close() { s.Pool.Close() }

// Entry mirrors the entries table. Structured holds parser-extracted fields.
type Entry struct {
	ID          int64           `json:"id"`
	ReceivedAt  time.Time       `json:"received_at"`
	DeviceTime  *time.Time      `json:"device_time,omitempty"`
	SourceID    *int64          `json:"source_id,omitempty"`
	SourceIP    string          `json:"source_ip,omitempty"`
	Facility    *int16          `json:"facility,omitempty"`
	Severity    int16           `json:"severity"`
	AppName     string          `json:"app_name"`
	Host        string          `json:"host"`
	Msg         string          `json:"msg"`
	Structured  json.RawMessage `json:"structured"`
	Priority    int16           `json:"priority"`
	Status      string          `json:"status"`
	Suppressed  bool            `json:"suppressed"`
	DeviceClass string          `json:"device_class"`
	Mitre       []string        `json:"mitre"`
	TagIDs      []int64         `json:"tag_ids"`

	// RuleTags carries (tag, rule) attribution from ingest-time rule
	// evaluation into InsertEntries; not serialized.
	RuleTags []RuleTag `json:"-"`

	// Notifies carries pending notifications a notify rule queued at ingest;
	// the dispatcher fires them after the entry is stored. Not serialized.
	Notifies []Notify `json:"-"`
}

// RuleTag records that a rule attached a tag, for the audit trail in
// entry_tags.rule_id.
type RuleTag struct {
	TagID  int64
	RuleID int64
}

// Notify records that a notify rule wants this entry delivered to a channel.
type Notify struct {
	ChannelID int64
	RuleID    int64
}

// FieldValue and HasTag make *Entry a rules.Record so the shared condition
// AST can match entries in memory (ingest rules, live tail).
func (e *Entry) FieldValue(name string) (any, bool) {
	switch name {
	case "host":
		return e.Host, true
	case "app_name":
		return e.AppName, true
	case "msg":
		return e.Msg, true
	case "status":
		return e.Status, true
	case "device_class":
		return e.DeviceClass, true
	case "mitre":
		return e.Mitre, true
	case "severity":
		return int64(e.Severity), true
	case "priority":
		return int64(e.Priority), true
	case "received_at":
		return e.ReceivedAt, true
	case "facility":
		if e.Facility == nil {
			return nil, false
		}
		return int64(*e.Facility), true
	case "source_id":
		if e.SourceID == nil {
			return nil, false
		}
		return *e.SourceID, true
	}
	if key, ok := strings.CutPrefix(name, "structured."); ok && len(e.Structured) > 0 {
		var m map[string]any
		if json.Unmarshal(e.Structured, &m) != nil {
			return nil, false
		}
		v, ok := m[key]
		if !ok {
			return nil, false
		}
		// Structured values compare as text, matching the ->> SQL operator.
		return fmt.Sprint(v), true
	}
	return nil, false
}

func (e *Entry) HasTag(id int64) bool {
	for _, t := range e.TagIDs {
		if t == id {
			return true
		}
	}
	return false
}

type Source struct {
	ID        int64     `json:"id"`
	IP        string    `json:"ip"`
	Hostname  string    `json:"hostname"`
	Vendor    string    `json:"vendor"`
	Zone      string    `json:"zone"`
	Site      string    `json:"site"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

// UpsertSource returns the id for a (hostname, ip) pair, creating the source
// on first sight and bumping last_seen otherwise.
func (s *Store) UpsertSource(ctx context.Context, hostname, ip string) (int64, error) {
	var id int64
	err := s.Pool.QueryRow(ctx, `
		INSERT INTO sources (hostname, ip)
		VALUES ($1, $2)
		ON CONFLICT (hostname, ip) DO UPDATE SET last_seen = now()
		RETURNING id`, hostname, ip).Scan(&id)
	return id, err
}

// InsertEntries bulk-inserts a batch, fills in the generated ids, and
// attaches any rule-applied tags. Returning ids (rather than COPY) is what
// lets the ingest path broadcast complete entries to live-tail clients.
func (s *Store) InsertEntries(ctx context.Context, entries []Entry) error {
	if len(entries) == 0 {
		return nil
	}
	const cols = 14
	var sb strings.Builder
	sb.WriteString(`INSERT INTO entries
		(received_at, device_time, source_id, facility, severity, app_name, host, msg, structured, priority, status, suppressed, device_class, mitre) VALUES `)
	args := make([]any, 0, len(entries)*cols)
	for i := range entries {
		e := &entries[i]
		structured := e.Structured
		if len(structured) == 0 {
			structured = json.RawMessage(`{}`)
		}
		mitre := e.Mitre
		if mitre == nil {
			mitre = []string{}
		}
		if i > 0 {
			sb.WriteByte(',')
		}
		sb.WriteByte('(')
		for j := 0; j < cols; j++ {
			if j > 0 {
				sb.WriteByte(',')
			}
			fmt.Fprintf(&sb, "$%d", i*cols+j+1)
		}
		sb.WriteByte(')')
		args = append(args, e.ReceivedAt, e.DeviceTime, e.SourceID, e.Facility, e.Severity,
			e.AppName, e.Host, e.Msg, structured, e.Priority, e.Status, e.Suppressed, e.DeviceClass, mitre)
	}
	// RETURNING rows come back in VALUES order for a plain INSERT.
	sb.WriteString(" RETURNING id")

	rows, err := s.Pool.Query(ctx, sb.String(), args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	for i := 0; rows.Next(); i++ {
		if err := rows.Scan(&entries[i].ID); err != nil {
			return err
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	return s.insertRuleTags(ctx, entries)
}

func (s *Store) insertRuleTags(ctx context.Context, entries []Entry) error {
	var sb strings.Builder
	var args []any
	for _, e := range entries {
		for _, rt := range e.RuleTags {
			if len(args) > 0 {
				sb.WriteByte(',')
			}
			fmt.Fprintf(&sb, "($%d,$%d,$%d)", len(args)+1, len(args)+2, len(args)+3)
			args = append(args, e.ID, rt.TagID, rt.RuleID)
		}
	}
	if len(args) == 0 {
		return nil
	}
	_, err := s.Pool.Exec(ctx,
		"INSERT INTO entry_tags (entry_id, tag_id, rule_id) VALUES "+sb.String()+" ON CONFLICT DO NOTHING",
		args...)
	return err
}

// EntryFilter selects entries via the shared condition AST plus pagination.
// Suppressed entries are hidden unless IncludeSuppressed is set (flagged, not deleted).
type EntryFilter struct {
	Cond              rules.Cond
	IncludeSuppressed bool
	BeforeID          *int64 // paginate older (time sort only)
	AfterID           *int64 // fetch newer; results ascend (time sort only)
	Sort              string // "" or "time" = received order; else a column key
	Desc              bool   // sort direction (time defaults to newest-first)
	Limit             int
}

// sortColumn maps a sort key to its SQL ordering expression. The default
// (time) orders by id, which is monotonic with received_at and lets the
// keyset pagination below stay on the primary key.
func sortColumn(key string) (expr string, isTime bool, ok bool) {
	switch key {
	case "", "time":
		return "e.id", true, true
	case "severity":
		return "e.severity", false, true
	case "priority":
		return "e.priority", false, true
	case "host":
		return "lower(e.host)", false, true
	case "app":
		return "lower(e.app_name)", false, true
	case "device_class":
		return "e.device_class", false, true
	}
	return "", false, false
}

func (s *Store) ListEntries(ctx context.Context, f EntryFilter) ([]Entry, error) {
	var conds []string
	var args []any
	arg := func(v any) string {
		args = append(args, v)
		return fmt.Sprintf("$%d", len(args))
	}

	condSQL, err := f.Cond.CompileSQL(arg)
	if err != nil {
		return nil, fmt.Errorf("compile condition: %w", err)
	}
	conds = append(conds, condSQL)
	if !f.IncludeSuppressed {
		conds = append(conds, "NOT e.suppressed")
	}
	expr, isTime, ok := sortColumn(f.Sort)
	if !ok {
		return nil, fmt.Errorf("unknown sort %q", f.Sort)
	}
	var order string
	if isTime {
		// Keyset pagination on the primary key (the original behaviour).
		if f.BeforeID != nil {
			conds = append(conds, "e.id < "+arg(*f.BeforeID))
		}
		order = "ORDER BY e.id DESC"
		if f.AfterID != nil {
			conds = append(conds, "e.id > "+arg(*f.AfterID))
			order = "ORDER BY e.id ASC"
		}
	} else {
		// A column sort returns one ranked page (the UI requests a wide
		// limit and re-sorts live arrivals client-side); id breaks ties so
		// the order is deterministic.
		dir := "ASC"
		if f.Desc {
			dir = "DESC"
		}
		order = fmt.Sprintf("ORDER BY %s %s, e.id DESC", expr, dir)
	}

	limit := f.Limit
	if limit <= 0 {
		limit = 100
	}
	if limit > 1000 {
		limit = 1000
	}

	sql := `SELECT e.id, e.received_at, e.device_time, e.source_id, COALESCE(s.ip, ''),
	               e.facility, e.severity, e.app_name, e.host, e.msg, e.structured, e.priority, e.status, e.suppressed,
	               e.device_class, e.mitre,
	               COALESCE((SELECT array_agg(et.tag_id ORDER BY et.tag_id) FROM entry_tags et WHERE et.entry_id = e.id), '{}')
	        FROM entries e LEFT JOIN sources s ON s.id = e.source_id`
	if len(conds) > 0 {
		sql += " WHERE " + strings.Join(conds, " AND ")
	}
	sql += " " + order + " LIMIT " + arg(limit)

	rows, err := s.Pool.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	entries := []Entry{}
	for rows.Next() {
		var e Entry
		if err := rows.Scan(&e.ID, &e.ReceivedAt, &e.DeviceTime, &e.SourceID, &e.SourceIP,
			&e.Facility, &e.Severity, &e.AppName, &e.Host, &e.Msg, &e.Structured, &e.Priority, &e.Status,
			&e.Suppressed, &e.DeviceClass, &e.Mitre, &e.TagIDs); err != nil {
			return nil, err
		}
		entries = append(entries, e)
	}
	return entries, rows.Err()
}

// MitreSummary counts entries per ATT&CK technique under the given filter
// (the same condition the entry list uses), so the MITRE view can show live
// counts per technique. Returns a technique-id → count map.
func (s *Store) MitreSummary(ctx context.Context, f EntryFilter) (map[string]int64, error) {
	var conds []string
	var args []any
	arg := func(v any) string {
		args = append(args, v)
		return fmt.Sprintf("$%d", len(args))
	}
	condSQL, err := f.Cond.CompileSQL(arg)
	if err != nil {
		return nil, fmt.Errorf("compile condition: %w", err)
	}
	conds = append(conds, condSQL)
	if !f.IncludeSuppressed {
		conds = append(conds, "NOT e.suppressed")
	}
	sql := `SELECT t, count(*) FROM entries e, unnest(e.mitre) t WHERE ` +
		strings.Join(conds, " AND ") + ` GROUP BY t`
	rows, err := s.Pool.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int64{}
	for rows.Next() {
		var id string
		var n int64
		if err := rows.Scan(&id, &n); err != nil {
			return nil, err
		}
		out[id] = n
	}
	return out, rows.Err()
}

func (s *Store) GetEntry(ctx context.Context, id int64) (*Entry, error) {
	f := EntryFilter{Limit: 1, IncludeSuppressed: true}
	rows, err := s.ListEntries(ctx, f.withID(id))
	if err != nil || len(rows) == 0 {
		return nil, err
	}
	return &rows[0], nil
}

// UpdateEntry patches triage fields (status, priority) and returns the
// refreshed entry.
func (s *Store) UpdateEntry(ctx context.Context, id int64, status *string, priority *int16) (*Entry, error) {
	sets := []string{}
	args := []any{id}
	if status != nil {
		args = append(args, *status)
		sets = append(sets, fmt.Sprintf("status = $%d", len(args)))
	}
	if priority != nil {
		args = append(args, *priority)
		sets = append(sets, fmt.Sprintf("priority = $%d", len(args)))
	}
	if len(sets) > 0 {
		tag, err := s.Pool.Exec(ctx, "UPDATE entries SET "+strings.Join(sets, ", ")+" WHERE id = $1", args...)
		if err != nil {
			return nil, err
		}
		if tag.RowsAffected() == 0 {
			return nil, nil
		}
	}
	return s.GetEntry(ctx, id)
}

// TagEntry attaches a tag manually (rule_id NULL); idempotent.
func (s *Store) TagEntry(ctx context.Context, entryID, tagID int64) error {
	_, err := s.Pool.Exec(ctx,
		`INSERT INTO entry_tags (entry_id, tag_id) VALUES ($1, $2) ON CONFLICT DO NOTHING`, entryID, tagID)
	return err
}

func (s *Store) UntagEntry(ctx context.Context, entryID, tagID int64) error {
	_, err := s.Pool.Exec(ctx,
		`DELETE FROM entry_tags WHERE entry_id = $1 AND tag_id = $2`, entryID, tagID)
	return err
}

// withID is a tiny helper so GetEntry can reuse the ListEntries scan path.
func (f EntryFilter) withID(id int64) EntryFilter {
	before := id + 1
	after := id - 1
	f.BeforeID = &before
	f.AfterID = &after
	return f
}

func (s *Store) ListSources(ctx context.Context) ([]Source, error) {
	rows, err := s.Pool.Query(ctx, `
		SELECT id, ip, hostname, vendor, zone, site, first_seen, last_seen
		FROM sources ORDER BY last_seen DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	sources := []Source{}
	for rows.Next() {
		var src Source
		if err := rows.Scan(&src.ID, &src.IP, &src.Hostname, &src.Vendor, &src.Zone, &src.Site, &src.FirstSeen, &src.LastSeen); err != nil {
			return nil, err
		}
		sources = append(sources, src)
	}
	return sources, rows.Err()
}

type Stats struct {
	ApproxTotal int64 `json:"approx_total"`
	LastMinute  int64 `json:"last_minute"`
}

func (s *Store) GetStats(ctx context.Context) (Stats, error) {
	var st Stats
	err := s.Pool.QueryRow(ctx, `
		SELECT GREATEST((SELECT reltuples::bigint FROM pg_class WHERE relname = 'entries'), 0),
		       (SELECT count(*) FROM entries WHERE received_at > now() - interval '60 seconds')`).
		Scan(&st.ApproxTotal, &st.LastMinute)
	return st, err
}
