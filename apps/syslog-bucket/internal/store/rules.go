package store

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/syslog-yard/syslog-bucket/internal/rules"
)

// Rule is a mail-filter analogue: condition + ordered actions.
type Rule struct {
	ID        int64          `json:"id"`
	Name      string         `json:"name"`
	Enabled   bool           `json:"enabled"`
	Position  int            `json:"position"`
	Condition rules.Cond     `json:"condition"`
	Actions   []rules.Action `json:"actions"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
}

func (s *Store) ListRules(ctx context.Context) ([]Rule, error) {
	rows, err := s.Pool.Query(ctx, `
		SELECT id, name, enabled, position, condition, actions, created_at, updated_at
		FROM rules ORDER BY position, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []Rule{}
	for rows.Next() {
		var r Rule
		var cond, actions []byte
		if err := rows.Scan(&r.ID, &r.Name, &r.Enabled, &r.Position, &cond, &actions, &r.CreatedAt, &r.UpdatedAt); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(cond, &r.Condition); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(actions, &r.Actions); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) GetRule(ctx context.Context, id int64) (*Rule, error) {
	all, err := s.ListRules(ctx)
	if err != nil {
		return nil, err
	}
	for _, r := range all {
		if r.ID == id {
			return &r, nil
		}
	}
	return nil, nil
}

func (s *Store) CreateRule(ctx context.Context, r Rule) (Rule, error) {
	cond, actions, err := marshalRule(r)
	if err != nil {
		return r, err
	}
	err = s.Pool.QueryRow(ctx, `
		INSERT INTO rules (name, enabled, position, condition, actions)
		VALUES ($1, $2, $3, $4, $5) RETURNING id, created_at, updated_at`,
		r.Name, r.Enabled, r.Position, cond, actions).Scan(&r.ID, &r.CreatedAt, &r.UpdatedAt)
	return r, err
}

func (s *Store) UpdateRule(ctx context.Context, r Rule) (bool, error) {
	cond, actions, err := marshalRule(r)
	if err != nil {
		return false, err
	}
	tag, err := s.Pool.Exec(ctx, `
		UPDATE rules SET name = $2, enabled = $3, position = $4, condition = $5, actions = $6, updated_at = now()
		WHERE id = $1`,
		r.ID, r.Name, r.Enabled, r.Position, cond, actions)
	return tag.RowsAffected() > 0, err
}

func (s *Store) DeleteRule(ctx context.Context, id int64) error {
	_, err := s.Pool.Exec(ctx, `DELETE FROM rules WHERE id = $1`, id)
	return err
}

func marshalRule(r Rule) (cond, actions []byte, err error) {
	if cond, err = json.Marshal(r.Condition); err != nil {
		return nil, nil, err
	}
	actions, err = json.Marshal(r.Actions)
	return cond, actions, err
}

// ApplyResult summarises a historical rule run.
type ApplyResult struct {
	// Affected is how many distinct entries at least one action changed
	// (the field name predates this struct; the UI reads it).
	Affected int64 `json:"affected"`
	// Matched is how many entries the condition selected.
	Matched int64 `json:"matched"`
	// Skipped lists action types that never run retroactively (notify: a
	// rule edit must not fire an alert storm for old entries).
	Skipped []string `json:"skipped"`
}

// ApplyRuleHistorical runs a rule's actions against all existing entries
// matching its condition — the retroactive half. Like the ingest engine, the
// condition is evaluated once: the matching ids are snapshotted first, so an
// action that changes a matched column (set_priority, suppress, …) can't
// change which entries later actions touch. All actions apply in a single
// transaction — an error leaves history untouched.
func (s *Store) ApplyRuleHistorical(ctx context.Context, r Rule) (ApplyResult, error) {
	res := ApplyResult{Skipped: []string{}}
	var args []any
	arg := func(v any) string {
		args = append(args, v)
		return fmt.Sprintf("$%d", len(args))
	}
	condSQL, err := r.Condition.CompileSQL(arg)
	if err != nil {
		return res, err
	}

	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return res, err
	}
	defer tx.Rollback(ctx) // no-op once committed

	if _, err := tx.Exec(ctx, `CREATE TEMP TABLE rule_apply_match (id BIGINT PRIMARY KEY) ON COMMIT DROP`); err != nil {
		return res, err
	}
	if _, err := tx.Exec(ctx, `CREATE TEMP TABLE rule_apply_touched (id BIGINT PRIMARY KEY) ON COMMIT DROP`); err != nil {
		return res, err
	}
	tag, err := tx.Exec(ctx, `INSERT INTO rule_apply_match SELECT e.id FROM entries e WHERE `+condSQL, args...)
	if err != nil {
		return res, fmt.Errorf("match entries: %w", err)
	}
	res.Matched = tag.RowsAffected()

	skipped := map[string]bool{}
	for _, a := range r.Actions {
		// Each statement records the ids it changed in rule_apply_touched, so
		// Affected counts entries, not action passes.
		var sql string
		var aargs []any
		switch a.Type {
		case "tag":
			sql = `WITH ch AS (
				INSERT INTO entry_tags (entry_id, tag_id, rule_id)
				SELECT m.id, t.id, $2::bigint FROM rule_apply_match m JOIN tags t ON t.id = $1::bigint
				ON CONFLICT DO NOTHING RETURNING entry_id)
				INSERT INTO rule_apply_touched SELECT entry_id FROM ch ON CONFLICT DO NOTHING`
			aargs = []any{a.TagID, r.ID}
		case "set_priority":
			sql = `WITH ch AS (
				UPDATE entries e SET priority = $1 FROM rule_apply_match m
				WHERE e.id = m.id AND e.priority IS DISTINCT FROM $1 RETURNING e.id)
				INSERT INTO rule_apply_touched SELECT id FROM ch ON CONFLICT DO NOTHING`
			aargs = []any{a.Priority}
		case "suppress":
			sql = `WITH ch AS (
				UPDATE entries e SET suppressed = TRUE FROM rule_apply_match m
				WHERE e.id = m.id AND NOT e.suppressed RETURNING e.id)
				INSERT INTO rule_apply_touched SELECT id FROM ch ON CONFLICT DO NOTHING`
		case "set_mitre", "set_ot":
			col, codes := "mitre", a.Mitre
			if a.Type == "set_ot" {
				col, codes = "ot", a.OT
			}
			if len(codes) == 0 {
				skipped[a.Type] = true
				continue
			}
			sql = fmt.Sprintf(`WITH ch AS (
				UPDATE entries e SET %[1]s = ARRAY(SELECT DISTINCT unnest(e.%[1]s || $1::text[]))
				FROM rule_apply_match m
				WHERE e.id = m.id AND NOT e.%[1]s @> $1::text[] RETURNING e.id)
				INSERT INTO rule_apply_touched SELECT id FROM ch ON CONFLICT DO NOTHING`, col)
			aargs = []any{codes}
		default:
			// notify (and anything newer) is ingest-only.
			skipped[a.Type] = true
			continue
		}
		if _, err := tx.Exec(ctx, sql, aargs...); err != nil {
			return ApplyResult{Skipped: []string{}}, fmt.Errorf("apply action %s: %w", a.Type, err)
		}
	}
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM rule_apply_touched`).Scan(&res.Affected); err != nil {
		return ApplyResult{Skipped: []string{}}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return ApplyResult{Skipped: []string{}}, err
	}
	for t := range skipped {
		res.Skipped = append(res.Skipped, t)
	}
	sort.Strings(res.Skipped)
	return res, nil
}
