package store

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/syslog-yard/syslog-bucket/internal/rules"
)

// Rule is a mail-filter analogue: condition + ordered actions (PLAN §5).
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

// ApplyRuleHistorical runs a rule's actions against all existing entries
// matching its condition — the retroactive half of PLAN §5. Returns the
// number of rows each pass touched.
func (s *Store) ApplyRuleHistorical(ctx context.Context, r Rule) (int64, error) {
	var total int64
	for _, a := range r.Actions {
		var args []any
		arg := func(v any) string {
			args = append(args, v)
			return fmt.Sprintf("$%d", len(args))
		}
		condSQL, err := r.Condition.CompileSQL(arg)
		if err != nil {
			return total, err
		}
		var sql string
		switch a.Type {
		case "tag":
			sql = fmt.Sprintf(`INSERT INTO entry_tags (entry_id, tag_id, rule_id)
				SELECT e.id, %s, %s FROM entries e WHERE %s
				ON CONFLICT DO NOTHING`, arg(a.TagID), arg(r.ID), condSQL)
		case "set_priority":
			sql = fmt.Sprintf(`UPDATE entries e SET priority = %s WHERE %s`, arg(a.Priority), condSQL)
		case "suppress":
			sql = fmt.Sprintf(`UPDATE entries e SET suppressed = TRUE WHERE %s AND NOT e.suppressed`, condSQL)
		default:
			continue
		}
		tag, err := s.Pool.Exec(ctx, sql, args...)
		if err != nil {
			return total, fmt.Errorf("apply action %s: %w", a.Type, err)
		}
		total += tag.RowsAffected()
	}
	return total, nil
}
