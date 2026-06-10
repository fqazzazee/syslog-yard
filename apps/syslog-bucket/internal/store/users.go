package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

func isNoRows(err error) bool { return errors.Is(err, pgx.ErrNoRows) }

// Roles, least to most privileged. Viewer is read-only, analyst owns the
// triage workflow, admin additionally manages users and every bucket.
const (
	RoleAdmin   = "admin"
	RoleAnalyst = "analyst"
	RoleViewer  = "viewer"
)

func ValidRole(r string) bool {
	return r == RoleAdmin || r == RoleAnalyst || r == RoleViewer
}

type User struct {
	ID          int64     `json:"id"`
	Username    string    `json:"username"`
	DisplayName string    `json:"display_name"`
	Email       string    `json:"email"`
	Role        string    `json:"role"`
	Disabled    bool      `json:"disabled"`
	HasPassword bool      `json:"has_password"`
	OIDC        bool      `json:"oidc"`
	CreatedAt   time.Time `json:"created_at"`

	// PasswordHash stays server-side; empty for OIDC-only accounts.
	PasswordHash string `json:"-"`
}

const userCols = `id, username, display_name, email, role, disabled,
	COALESCE(password_hash, ''), oidc_subject IS NOT NULL, created_at`

func scanUser(row interface{ Scan(...any) error }) (*User, error) {
	var u User
	if err := row.Scan(&u.ID, &u.Username, &u.DisplayName, &u.Email, &u.Role,
		&u.Disabled, &u.PasswordHash, &u.OIDC, &u.CreatedAt); err != nil {
		return nil, err
	}
	u.HasPassword = u.PasswordHash != ""
	return &u, nil
}

func (s *Store) CountUsers(ctx context.Context) (int64, error) {
	var n int64
	err := s.Pool.QueryRow(ctx, `SELECT count(*) FROM users`).Scan(&n)
	return n, err
}

func (s *Store) ListUsers(ctx context.Context) ([]User, error) {
	rows, err := s.Pool.Query(ctx, `SELECT `+userCols+` FROM users ORDER BY username`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	users := []User{}
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		users = append(users, *u)
	}
	return users, rows.Err()
}

func (s *Store) GetUser(ctx context.Context, id int64) (*User, error) {
	return s.getUserWhere(ctx, `id = $1`, id)
}

func (s *Store) GetUserByUsername(ctx context.Context, username string) (*User, error) {
	return s.getUserWhere(ctx, `username = $1`, username)
}

func (s *Store) GetUserByOIDCSubject(ctx context.Context, subject string) (*User, error) {
	return s.getUserWhere(ctx, `oidc_subject = $1`, subject)
}

func (s *Store) getUserWhere(ctx context.Context, where string, arg any) (*User, error) {
	u, err := scanUser(s.Pool.QueryRow(ctx, `SELECT `+userCols+` FROM users WHERE `+where, arg))
	if err != nil {
		if isNoRows(err) {
			return nil, nil
		}
		return nil, err
	}
	return u, nil
}

// CreateUser inserts a user; passwordHash may be empty (OIDC-only) and
// oidcSubject empty (local-only).
func (s *Store) CreateUser(ctx context.Context, u User, oidcSubject string) (User, error) {
	err := s.Pool.QueryRow(ctx, `
		INSERT INTO users (username, display_name, email, role, password_hash, oidc_subject)
		VALUES ($1, $2, $3, $4, NULLIF($5, ''), NULLIF($6, ''))
		RETURNING id, created_at`,
		u.Username, u.DisplayName, u.Email, u.Role, u.PasswordHash, oidcSubject).
		Scan(&u.ID, &u.CreatedAt)
	u.HasPassword = u.PasswordHash != ""
	u.OIDC = oidcSubject != ""
	return u, err
}

// UpdateUser patches profile fields; the password is changed separately via
// SetPassword so callers can't clear it by omission.
func (s *Store) UpdateUser(ctx context.Context, id int64, displayName, email, role string, disabled bool) (bool, error) {
	tag, err := s.Pool.Exec(ctx, `
		UPDATE users SET display_name = $2, email = $3, role = $4, disabled = $5
		WHERE id = $1`, id, displayName, email, role, disabled)
	return tag.RowsAffected() > 0, err
}

func (s *Store) SetPassword(ctx context.Context, id int64, hash string) (bool, error) {
	tag, err := s.Pool.Exec(ctx, `UPDATE users SET password_hash = $2 WHERE id = $1`, id, hash)
	return tag.RowsAffected() > 0, err
}

func (s *Store) DeleteUser(ctx context.Context, id int64) error {
	_, err := s.Pool.Exec(ctx, `DELETE FROM users WHERE id = $1`, id)
	return err
}

// --- sessions ---

func (s *Store) CreateSession(ctx context.Context, tokenHash string, userID int64, expires time.Time) error {
	// Piggyback expired-session cleanup on logins instead of a scheduler.
	if _, err := s.Pool.Exec(ctx, `DELETE FROM sessions WHERE expires_at < now()`); err != nil {
		return err
	}
	_, err := s.Pool.Exec(ctx,
		`INSERT INTO sessions (token_hash, user_id, expires_at) VALUES ($1, $2, $3)`,
		tokenHash, userID, expires)
	return err
}

// GetSessionUser resolves a session token hash to its (active) user, or nil
// when the session is missing, expired, or the account is disabled.
func (s *Store) GetSessionUser(ctx context.Context, tokenHash string) (*User, error) {
	u, err := scanUser(s.Pool.QueryRow(ctx, `
		SELECT `+userCols+` FROM users
		WHERE NOT disabled AND id = (
			SELECT user_id FROM sessions WHERE token_hash = $1 AND expires_at > now()
		)`, tokenHash))
	if err != nil {
		if isNoRows(err) {
			return nil, nil
		}
		return nil, err
	}
	return u, nil
}

func (s *Store) DeleteSession(ctx context.Context, tokenHash string) error {
	_, err := s.Pool.Exec(ctx, `DELETE FROM sessions WHERE token_hash = $1`, tokenHash)
	return err
}

// DeleteUserSessions logs a user out everywhere (password change, disable).
func (s *Store) DeleteUserSessions(ctx context.Context, userID int64) error {
	_, err := s.Pool.Exec(ctx, `DELETE FROM sessions WHERE user_id = $1`, userID)
	return err
}
