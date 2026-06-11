package store

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// Channel is a notification destination (S9). Config is kind-specific JSON:
//   - webhook / slack: {"url": "https://..."}
//   - smtp:            {"host","port","username","password","from","to":[],"tls":"starttls|tls|none"}
//
// RatePerMin caps deliveries to avoid alert storms (0 = unlimited).
type Channel struct {
	ID         int64           `json:"id"`
	Name       string          `json:"name"`
	Kind       string          `json:"kind"`
	Config     json.RawMessage `json:"config"`
	Enabled    bool            `json:"enabled"`
	RatePerMin int             `json:"rate_per_min"`
	CreatedAt  time.Time       `json:"created_at"`
}

func (s *Store) ListChannels(ctx context.Context) ([]Channel, error) {
	rows, err := s.Pool.Query(ctx, `
		SELECT id, name, kind, config, enabled, rate_per_min, created_at
		FROM notification_channels ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []Channel{}
	for rows.Next() {
		var c Channel
		if err := rows.Scan(&c.ID, &c.Name, &c.Kind, &c.Config, &c.Enabled, &c.RatePerMin, &c.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *Store) GetChannel(ctx context.Context, id int64) (*Channel, error) {
	var c Channel
	err := s.Pool.QueryRow(ctx, `
		SELECT id, name, kind, config, enabled, rate_per_min, created_at
		FROM notification_channels WHERE id = $1`, id).
		Scan(&c.ID, &c.Name, &c.Kind, &c.Config, &c.Enabled, &c.RatePerMin, &c.CreatedAt)
	if isNoRows(err) {
		return nil, nil
	}
	return &c, err
}

func (s *Store) CreateChannel(ctx context.Context, c Channel) (Channel, error) {
	if len(c.Config) == 0 {
		c.Config = json.RawMessage(`{}`)
	}
	err := s.Pool.QueryRow(ctx, `
		INSERT INTO notification_channels (name, kind, config, enabled, rate_per_min)
		VALUES ($1, $2, $3, $4, $5) RETURNING id, created_at`,
		c.Name, c.Kind, c.Config, c.Enabled, c.RatePerMin).Scan(&c.ID, &c.CreatedAt)
	return c, err
}

func (s *Store) UpdateChannel(ctx context.Context, c Channel) (bool, error) {
	if len(c.Config) == 0 {
		c.Config = json.RawMessage(`{}`)
	}
	tag, err := s.Pool.Exec(ctx, `
		UPDATE notification_channels
		SET name = $2, kind = $3, config = $4, enabled = $5, rate_per_min = $6
		WHERE id = $1`,
		c.ID, c.Name, c.Kind, c.Config, c.Enabled, c.RatePerMin)
	return tag.RowsAffected() > 0, err
}

func (s *Store) DeleteChannel(ctx context.Context, id int64) error {
	_, err := s.Pool.Exec(ctx, `DELETE FROM notification_channels WHERE id = $1`, id)
	return err
}

// Delivery is one row of the notification_log.
type Delivery struct {
	ID        int64     `json:"id"`
	ChannelID int64     `json:"channel_id"`
	EntryID   *int64    `json:"entry_id,omitempty"`
	RuleID    *int64    `json:"rule_id,omitempty"`
	Status    string    `json:"status"`
	Detail    string    `json:"detail"`
	SentAt    time.Time `json:"sent_at"`
}

func (s *Store) LogDelivery(ctx context.Context, d Delivery) error {
	_, err := s.Pool.Exec(ctx, `
		INSERT INTO notification_log (channel_id, entry_id, rule_id, status, detail)
		VALUES ($1, $2, $3, $4, $5)`,
		d.ChannelID, d.EntryID, d.RuleID, d.Status, d.Detail)
	return err
}

// RecentDeliveries returns the latest deliveries, optionally for one channel.
func (s *Store) RecentDeliveries(ctx context.Context, channelID *int64, limit int) ([]Delivery, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	sql := `SELECT id, channel_id, entry_id, rule_id, status, detail, sent_at
	        FROM notification_log`
	args := []any{}
	if channelID != nil {
		sql += ` WHERE channel_id = $1`
		args = append(args, *channelID)
	}
	args = append(args, limit)
	sql += fmt.Sprintf(" ORDER BY sent_at DESC, id DESC LIMIT $%d", len(args))

	rows, err := s.Pool.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Delivery{}
	for rows.Next() {
		var d Delivery
		if err := rows.Scan(&d.ID, &d.ChannelID, &d.EntryID, &d.RuleID, &d.Status, &d.Detail, &d.SentAt); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// PruneDeliveries deletes log rows older than the cutoff (keeps the table
// bounded; called periodically by the dispatcher).
func (s *Store) PruneDeliveries(ctx context.Context, olderThan time.Duration) error {
	_, err := s.Pool.Exec(ctx,
		`DELETE FROM notification_log WHERE sent_at < now() - make_interval(secs => $1)`,
		olderThan.Seconds())
	return err
}
