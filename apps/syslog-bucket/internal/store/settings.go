package store

import (
	"context"
	"encoding/json"
)

// app_settings holds runtime, admin-editable configuration as one JSON document
// per key (e.g. "oidc", "session"). It lets settings that used to be
// startup-only env vars change without a restart.

// GetSetting returns the raw JSON document for key. ok=false when no row exists
// (the caller falls back to an env-derived default).
func (s *Store) GetSetting(ctx context.Context, key string) (json.RawMessage, bool, error) {
	var raw []byte
	err := s.Pool.QueryRow(ctx, `SELECT value FROM app_settings WHERE key = $1`, key).Scan(&raw)
	if isNoRows(err) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return raw, true, nil
}

// PutSetting upserts the JSON document for key.
func (s *Store) PutSetting(ctx context.Context, key string, value any) error {
	doc, err := json.Marshal(value)
	if err != nil {
		return err
	}
	_, err = s.Pool.Exec(ctx,
		`INSERT INTO app_settings (key, value) VALUES ($1, $2)
		 ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()`,
		key, doc)
	return err
}
