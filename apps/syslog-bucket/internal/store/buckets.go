package store

import (
	"context"
	"encoding/json"
	"time"

	"github.com/syslog-yard/syslog-bucket/internal/rules"
)

// Bucket is a virtual folder: a saved condition, not stored rows.
// OwnerID NULL marks a shared "yard bucket" (unowned) visible to
// everyone and editable by admins/analysts; otherwise visibility is owner +
// shares + admins, with per-share can_edit.
type Bucket struct {
	ID          int64      `json:"id"`
	Name        string     `json:"name"`
	Description string     `json:"description"`
	Condition   rules.Cond `json:"condition"`
	Position    int        `json:"position"`
	OwnerID     *int64     `json:"owner_id,omitempty"`
	OwnerName   string     `json:"owner_name,omitempty"`
	CanEdit     bool       `json:"can_edit"`
	Shared      bool       `json:"shared"` // has at least one share entry
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
}

// ListBuckets returns the buckets visible to u with CanEdit computed for
// that user. A nil user (internal callers) sees everything, read-only.
func (s *Store) ListBuckets(ctx context.Context, u *User) ([]Bucket, error) {
	var uid int64 = -1
	admin, writer := false, false
	if u != nil {
		uid = u.ID
		admin = u.Role == RoleAdmin
		writer = u.Role == RoleAdmin || u.Role == RoleAnalyst
	}
	sql := `
		SELECT b.id, b.name, b.description, b.condition, b.position,
		       b.owner_id, COALESCE(o.username, ''),
		       CASE WHEN $2 THEN TRUE
		            WHEN b.owner_id = $1 THEN TRUE
		            WHEN b.owner_id IS NULL THEN $3
		            ELSE COALESCE(sh.can_edit, FALSE) END,
		       EXISTS (SELECT 1 FROM bucket_shares x WHERE x.bucket_id = b.id),
		       b.created_at, b.updated_at
		FROM buckets b
		LEFT JOIN users o ON o.id = b.owner_id
		LEFT JOIN bucket_shares sh ON sh.bucket_id = b.id AND sh.user_id = $1`
	if u != nil && !admin {
		sql += ` WHERE b.owner_id IS NULL OR b.owner_id = $1 OR sh.user_id IS NOT NULL`
	}
	sql += ` ORDER BY b.position, b.name`

	rows, err := s.Pool.Query(ctx, sql, uid, admin, writer)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	buckets := []Bucket{}
	for rows.Next() {
		var b Bucket
		var cond []byte
		if err := rows.Scan(&b.ID, &b.Name, &b.Description, &cond, &b.Position,
			&b.OwnerID, &b.OwnerName, &b.CanEdit, &b.Shared, &b.CreatedAt, &b.UpdatedAt); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(cond, &b.Condition); err != nil {
			return nil, err
		}
		if u == nil {
			b.CanEdit = false
		}
		buckets = append(buckets, b)
	}
	return buckets, rows.Err()
}

// GetBucket returns the bucket only if it is visible to u (nil = no check),
// so a guessed bucket_id can't leak another user's saved search.
func (s *Store) GetBucket(ctx context.Context, id int64, u *User) (*Bucket, error) {
	buckets, err := s.ListBuckets(ctx, u)
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

// SeedDefaultBuckets installs a curated set of saved searches reflecting a
// realistic SOC triage workload — but only when no buckets exist yet, so it
// never clobbers a deployment's own. They are ownerless "yard buckets",
// visible to everyone. Returns how many were created.
func (s *Store) SeedDefaultBuckets(ctx context.Context) (int, error) {
	var n int
	if err := s.Pool.QueryRow(ctx, `SELECT count(*) FROM buckets`).Scan(&n); err != nil {
		return 0, err
	}
	if n > 0 {
		return 0, nil
	}
	defs := defaultBuckets()
	for i := range defs {
		defs[i].Position = i + 1
		if _, err := s.CreateBucket(ctx, defs[i]); err != nil {
			return i, err
		}
	}
	return len(defs), nil
}

// defaultBuckets is the shipped SOC workload. Conditions ride the same
// mitre/ot/severity/status tags the bucket already computes at ingest.
func defaultBuckets() []Bucket {
	mitreLeaf := func(id string) rules.Cond { return rules.Cond{Mitre: id} }
	otLeaf := func(id string) rules.Cond { return rules.Cond{OT: id} }
	anyMitre := func(ids ...string) rules.Cond {
		c := rules.Cond{}
		for _, id := range ids {
			c.Any = append(c.Any, mitreLeaf(id))
		}
		return c
	}
	anyOT := func(ids ...string) rules.Cond {
		c := rules.Cond{}
		for _, id := range ids {
			c.Any = append(c.Any, otLeaf(id))
		}
		return c
	}
	b := func(name, desc string, c rules.Cond) Bucket {
		return Bucket{Name: name, Description: desc, Condition: c}
	}
	return []Bucket{
		b("Critical & high", "Severity emergency–error — look here first",
			rules.Cond{Field: "severity", Op: "lte", Value: float64(3)}),
		b("New / untriaged", "Unreviewed entries of notable severity",
			rules.Cond{All: []rules.Cond{
				{Field: "status", Op: "eq", Value: "new"},
				{Field: "severity", Op: "lte", Value: float64(4)},
			}}),
		b("Exploitation attempts", "Exploit of public-facing apps (ATT&CK T1190)", mitreLeaf("T1190")),
		b("Brute force & auth failures", "Password guessing (ATT&CK T1110)", mitreLeaf("T1110")),
		b("Suspicious logins", "Use of valid accounts (ATT&CK T1078)", mitreLeaf("T1078")),
		b("Malware & phishing", "User execution / phishing (T1204, T1566)", anyMitre("T1204", "T1566")),
		b("Command & control", "C2 / beaconing (ATT&CK T1071)", mitreLeaf("T1071")),
		b("Lateral movement", "Remote services (ATT&CK T1021)", mitreLeaf("T1021")),
		b("Privilege escalation", "Elevation control abuse (ATT&CK T1548)", mitreLeaf("T1548")),
		b("OT security alerts", "Claroty Security alerts on the OT network",
			anyOT("CL-KT", "CL-SUS", "CL-SCAN", "CL-UA", "CL-POL", "CL-MAL")),
		b("OT integrity changes", "Claroty Integrity alerts — asset/config/PLC changes",
			anyOT("CL-NEWA", "CL-CHG", "CL-BASE", "CL-CFG", "CL-MODE", "CL-CONF")),
	}
}

func (s *Store) CreateBucket(ctx context.Context, b Bucket) (Bucket, error) {
	cond, err := json.Marshal(b.Condition)
	if err != nil {
		return b, err
	}
	err = s.Pool.QueryRow(ctx, `
		INSERT INTO buckets (name, description, condition, position, owner_id)
		VALUES ($1, $2, $3, $4, $5) RETURNING id, created_at, updated_at`,
		b.Name, b.Description, cond, b.Position, b.OwnerID).Scan(&b.ID, &b.CreatedAt, &b.UpdatedAt)
	b.CanEdit = true
	return b, err
}

// UpdateBucket changes content fields only; ownership moves are not a thing
// in v1 (delete and recreate instead).
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

// --- shares ---

// BucketShare grants one user visibility of (and optionally edit rights on)
// someone else's bucket.
type BucketShare struct {
	UserID      int64  `json:"user_id"`
	Username    string `json:"username"`
	DisplayName string `json:"display_name"`
	CanEdit     bool   `json:"can_edit"`
}

func (s *Store) ListBucketShares(ctx context.Context, bucketID int64) ([]BucketShare, error) {
	rows, err := s.Pool.Query(ctx, `
		SELECT sh.user_id, u.username, u.display_name, sh.can_edit
		FROM bucket_shares sh JOIN users u ON u.id = sh.user_id
		WHERE sh.bucket_id = $1 ORDER BY u.username`, bucketID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	shares := []BucketShare{}
	for rows.Next() {
		var sh BucketShare
		if err := rows.Scan(&sh.UserID, &sh.Username, &sh.DisplayName, &sh.CanEdit); err != nil {
			return nil, err
		}
		shares = append(shares, sh)
	}
	return shares, rows.Err()
}

// ReplaceBucketShares swaps the full share list in one transaction — the
// share dialog always submits its complete state.
func (s *Store) ReplaceBucketShares(ctx context.Context, bucketID int64, shares []BucketShare) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	if _, err := tx.Exec(ctx, `DELETE FROM bucket_shares WHERE bucket_id = $1`, bucketID); err != nil {
		return err
	}
	for _, sh := range shares {
		if _, err := tx.Exec(ctx, `
			INSERT INTO bucket_shares (bucket_id, user_id, can_edit) VALUES ($1, $2, $3)
			ON CONFLICT (bucket_id, user_id) DO UPDATE SET can_edit = EXCLUDED.can_edit`,
			bucketID, sh.UserID, sh.CanEdit); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}
