package store

import (
	"context"
)

// Tag is a color-coded label, the email-client "label/flag" (PLAN §1).
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

func (s *Store) DeleteTag(ctx context.Context, id int64) error {
	_, err := s.Pool.Exec(ctx, `DELETE FROM tags WHERE id = $1`, id)
	return err
}
