package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// Tag is a color-coded label, the email-client "label/flag".
type Tag struct {
	ID          int64  `json:"id"`
	Name        string `json:"name"`
	Color       string `json:"color"`
	Description string `json:"description"`
}

func (s *Store) ListTags(ctx context.Context) ([]Tag, error) {
	rows, err := s.Pool.Query(ctx, `SELECT id, name, color, description FROM tags ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	tags := []Tag{}
	for rows.Next() {
		var t Tag
		if err := rows.Scan(&t.ID, &t.Name, &t.Color, &t.Description); err != nil {
			return nil, err
		}
		tags = append(tags, t)
	}
	return tags, rows.Err()
}

func (s *Store) CreateTag(ctx context.Context, t Tag) (Tag, error) {
	err := s.Pool.QueryRow(ctx,
		`INSERT INTO tags (name, color, description) VALUES ($1, $2, $3) RETURNING id`,
		t.Name, t.Color, t.Description).Scan(&t.ID)
	return t, err
}

func (s *Store) UpdateTag(ctx context.Context, t Tag) (bool, error) {
	tag, err := s.Pool.Exec(ctx,
		`UPDATE tags SET name = $2, color = $3, description = $4 WHERE id = $1`,
		t.ID, t.Name, t.Color, t.Description)
	return tag.RowsAffected() > 0, err
}

// DeleteTag removes a tag (and, by cascade, its entry associations). It
// refuses with an *InUseError while an enabled rule's tag action points at
// the tag: deleting it would silently break that rule.
func (s *Store) DeleteTag(ctx context.Context, id int64) error {
	names, err := s.rulesReferencing(ctx, "tag", "tag_id", id)
	if err != nil {
		return err
	}
	if len(names) > 0 {
		return &InUseError{What: "tag", Rules: names}
	}
	_, err = s.Pool.Exec(ctx, `DELETE FROM tags WHERE id = $1`, id)
	return err
}

// ErrInUse is wrapped by *InUseError; match it with errors.Is.
var ErrInUse = errors.New("in use")

// InUseError reports that a tag or channel can't be deleted because enabled
// rules reference it.
type InUseError struct {
	What  string   // "tag" | "channel"
	Rules []string // names of the referencing enabled rules
}

func (e *InUseError) Error() string {
	return fmt.Sprintf("%s is used by enabled rule(s): %s — remove it from those rules or disable them first",
		e.What, strings.Join(e.Rules, ", "))
}

func (e *InUseError) Unwrap() error { return ErrInUse }

// rulesReferencing names the enabled rules with an action of actionType whose
// idKey equals id.
func (s *Store) rulesReferencing(ctx context.Context, actionType, idKey string, id int64) ([]string, error) {
	rows, err := s.Pool.Query(ctx, `
		SELECT r.name FROM rules r
		WHERE r.enabled AND EXISTS (
			SELECT 1 FROM jsonb_array_elements(r.actions) a
			WHERE a->>'type' = $1 AND a->$2 = to_jsonb($3::bigint))
		ORDER BY r.position, r.id`, actionType, idKey, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var names []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, err
		}
		names = append(names, n)
	}
	return names, rows.Err()
}

// MissingRuleRefs returns the tag and channel ids that rule actions refer to
// but that don't exist, so a rule can't be saved pointing at nothing.
func (s *Store) MissingRuleRefs(ctx context.Context, tagIDs, channelIDs []int64) (missingTags, missingChannels []int64, err error) {
	missing := func(table string, ids []int64) ([]int64, error) {
		if len(ids) == 0 {
			return nil, nil
		}
		rows, err := s.Pool.Query(ctx, `
			SELECT DISTINCT i FROM unnest($1::bigint[]) AS i
			WHERE NOT EXISTS (SELECT 1 FROM `+table+` t WHERE t.id = i)
			ORDER BY i`, ids)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		var out []int64
		for rows.Next() {
			var id int64
			if err := rows.Scan(&id); err != nil {
				return nil, err
			}
			out = append(out, id)
		}
		return out, rows.Err()
	}
	if missingTags, err = missing("tags", tagIDs); err != nil {
		return nil, nil, err
	}
	missingChannels, err = missing("notification_channels", channelIDs)
	return missingTags, missingChannels, err
}
