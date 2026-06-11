-- tags, buckets, rules. Buckets and rules store a condition
-- AST as JSONB; rules add an ordered actions array. Suppression flags
-- entries instead of deleting them so a rule mistake is recoverable.

ALTER TABLE entries ADD COLUMN suppressed BOOLEAN NOT NULL DEFAULT FALSE;

CREATE TABLE tags (
    id          BIGSERIAL PRIMARY KEY,
    org_id      BIGINT,
    name        TEXT NOT NULL UNIQUE,
    color       TEXT NOT NULL DEFAULT '#8a94a6',
    description TEXT NOT NULL DEFAULT ''
);

CREATE TABLE rules (
    id          BIGSERIAL PRIMARY KEY,
    org_id      BIGINT,
    name        TEXT    NOT NULL UNIQUE,
    enabled     BOOLEAN NOT NULL DEFAULT TRUE,
    position    INT     NOT NULL DEFAULT 0,
    condition   JSONB   NOT NULL DEFAULT '{}',
    actions     JSONB   NOT NULL DEFAULT '[]',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE entry_tags (
    entry_id  BIGINT NOT NULL REFERENCES entries(id) ON DELETE CASCADE,
    tag_id    BIGINT NOT NULL REFERENCES tags(id)    ON DELETE CASCADE,
    rule_id   BIGINT REFERENCES rules(id) ON DELETE SET NULL,  -- NULL = manual
    tagged_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (entry_id, tag_id)
);
CREATE INDEX entry_tags_tag ON entry_tags (tag_id);

CREATE TABLE buckets (
    id          BIGSERIAL PRIMARY KEY,
    org_id      BIGINT,
    name        TEXT  NOT NULL UNIQUE,
    description TEXT  NOT NULL DEFAULT '',
    condition   JSONB NOT NULL DEFAULT '{}',
    position    INT   NOT NULL DEFAULT 0,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
