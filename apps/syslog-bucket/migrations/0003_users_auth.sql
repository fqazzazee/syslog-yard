-- users, sessions, bucket ownership + sharing.
-- A NULL password_hash means OIDC-only; a NULL oidc_subject means local-only.
-- Buckets created before this migration keep owner_id NULL = a shared "yard
-- bucket" everyone sees and admins/analysts may edit.

CREATE TABLE users (
    id            BIGSERIAL PRIMARY KEY,
    org_id        BIGINT,
    username      TEXT NOT NULL UNIQUE,
    display_name  TEXT NOT NULL DEFAULT '',
    email         TEXT NOT NULL DEFAULT '',
    role          TEXT NOT NULL DEFAULT 'analyst'
                  CHECK (role IN ('admin', 'analyst', 'viewer')),
    password_hash TEXT,
    oidc_subject  TEXT UNIQUE,
    disabled      BOOLEAN NOT NULL DEFAULT FALSE,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Opaque session tokens live in the browser cookie; only their SHA-256 is
-- stored, so a database leak does not leak live sessions.
CREATE TABLE sessions (
    token_hash TEXT PRIMARY KEY,
    user_id    BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX sessions_user ON sessions (user_id);

ALTER TABLE buckets ADD COLUMN owner_id BIGINT REFERENCES users(id) ON DELETE SET NULL;

CREATE TABLE bucket_shares (
    bucket_id BIGINT NOT NULL REFERENCES buckets(id) ON DELETE CASCADE,
    user_id   BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    can_edit  BOOLEAN NOT NULL DEFAULT FALSE,
    shared_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (bucket_id, user_id)
);
CREATE INDEX bucket_shares_user ON bucket_shares (user_id);
