package store

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/syslog-yard/syslog-bucket/internal/frameworks"
)

// Custom frameworks are site-defined crosswalks stored as a single
// frameworks.Framework document each. The id the UI sees is "custom-<dbid>"; the
// numeric db id is the source of truth. The built-in catalogs (internal/
// frameworks) never live here — the API layer merges the two.
const customPrefix = "custom-"

func customID(id int64) string { return customPrefix + strconv.FormatInt(id, 10) }

func parseCustomID(fwID string) (int64, bool) {
	rest, ok := strings.CutPrefix(fwID, customPrefix)
	if !ok {
		return 0, false
	}
	n, err := strconv.ParseInt(rest, 10, 64)
	if err != nil {
		return 0, false
	}
	return n, true
}

func (s *Store) ListCustomFrameworks(ctx context.Context) ([]frameworks.Framework, error) {
	rows, err := s.Pool.Query(ctx, `SELECT id, doc FROM custom_frameworks ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []frameworks.Framework{}
	for rows.Next() {
		var id int64
		var doc []byte
		if err := rows.Scan(&id, &doc); err != nil {
			return nil, err
		}
		var f frameworks.Framework
		if err := json.Unmarshal(doc, &f); err != nil {
			return nil, fmt.Errorf("custom framework %d: %w", id, err)
		}
		f.ID = customID(id)
		out = append(out, f)
	}
	return out, rows.Err()
}

// GetCustomFramework returns one framework by its "custom-<id>" id. ok=false for
// a malformed id, a missing row, or unreadable JSON (all "not a known framework"
// from the caller's point of view).
func (s *Store) GetCustomFramework(ctx context.Context, fwID string) (frameworks.Framework, bool) {
	id, ok := parseCustomID(fwID)
	if !ok {
		return frameworks.Framework{}, false
	}
	var doc []byte
	if err := s.Pool.QueryRow(ctx, `SELECT doc FROM custom_frameworks WHERE id = $1`, id).Scan(&doc); err != nil {
		return frameworks.Framework{}, false
	}
	var f frameworks.Framework
	if err := json.Unmarshal(doc, &f); err != nil {
		return frameworks.Framework{}, false
	}
	f.ID = customID(id)
	return f, true
}

func (s *Store) CreateCustomFramework(ctx context.Context, f frameworks.Framework) (frameworks.Framework, error) {
	f.ID = "" // the db id is authoritative; don't persist the synthetic one
	doc, err := json.Marshal(f)
	if err != nil {
		return f, err
	}
	var id int64
	if err := s.Pool.QueryRow(ctx,
		`INSERT INTO custom_frameworks (doc) VALUES ($1) RETURNING id`, doc).Scan(&id); err != nil {
		return f, err
	}
	f.ID = customID(id)
	return f, nil
}

func (s *Store) UpdateCustomFramework(ctx context.Context, fwID string, f frameworks.Framework) (bool, error) {
	id, ok := parseCustomID(fwID)
	if !ok {
		return false, nil
	}
	f.ID = ""
	doc, err := json.Marshal(f)
	if err != nil {
		return false, err
	}
	tag, err := s.Pool.Exec(ctx,
		`UPDATE custom_frameworks SET doc = $2, updated_at = now() WHERE id = $1`, id, doc)
	return tag.RowsAffected() > 0, err
}

func (s *Store) DeleteCustomFramework(ctx context.Context, fwID string) (bool, error) {
	id, ok := parseCustomID(fwID)
	if !ok {
		return false, nil
	}
	tag, err := s.Pool.Exec(ctx, `DELETE FROM custom_frameworks WHERE id = $1`, id)
	return tag.RowsAffected() > 0, err
}
