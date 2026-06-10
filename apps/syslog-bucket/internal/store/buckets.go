package store

import (
	"context"
	"encoding/json"
	"time"

	"github.com/syslog-yard/syslog-bucket/internal/rules"
)

// Bucket is a virtual folder: a saved condition, not stored rows (PLAN §4).
type Bucket struct {
	ID          int64      `json:"id"`
	Name        string     `json:"name"`
	Description string     `json:"description"`
	Condition   rules.Cond `json:"condition"`
	Position    int        `json:"position"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
}

func (s *Store) ListBuckets(ctx context.Context) ([]Bucket, error) {
	rows, err := s.Pool.Query(ctx, `
		SELECT id, name, description, condition, position, created_at, updated_at
		FROM buckets ORDER BY position, name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	buckets := []Bucket{}
	for rows.Next() {
		var b Bucket
		var cond []byte
		if err := rows.Scan(&b.ID, &b.Name, &b.Description, &cond, &b.Position, &b.CreatedAt, &b.UpdatedAt); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(cond, &b.Condition); err != nil {
			return nil, err
		}
		buckets = append(buckets, b)
	}
	return buckets, rows.Err()
}

func (s *Store) GetBucket(ctx context.Context, id int64) (*Bucket, error) {
	buckets, err := s.ListBuckets(ctx)
	if err != nil {
		return nil, err
	}
	for _, b := range buckets {
		if b.ID == id {
			return &b, nil
		}
	}
	return nil, nil
}

func (s *Store) CreateBucket(ctx context.Context, b Bucket) (Bucket, error) {
	cond, err := json.Marshal(b.Condition)
	if err != nil {
		return b, err
	}
	err = s.Pool.QueryRow(ctx, `
		INSERT INTO buckets (name, description, condition, position)
		VALUES ($1, $2, $3, $4) RETURNING id, created_at, updated_at`,
		b.Name, b.Description, cond, b.Position).Scan(&b.ID, &b.CreatedAt, &b.UpdatedAt)
	return b, err
}

func (s *Store) UpdateBucket(ctx context.Context, b Bucket) (bool, error) {
	cond, err := json.Marshal(b.Condition)
	if err != nil {
		return false, err
	}
	tag, err := s.Pool.Exec(ctx, `
		UPDATE buckets SET name = $2, description = $3, condition = $4, position = $5, updated_at = now()
		WHERE id = $1`,
		b.ID, b.Name, b.Description, cond, b.Position)
	return tag.RowsAffected() > 0, err
}

func (s *Store) DeleteBucket(ctx context.Context, id int64) error {
	_, err := s.Pool.Exec(ctx, `DELETE FROM buckets WHERE id = $1`, id)
	return err
}
