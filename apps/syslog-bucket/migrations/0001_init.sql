-- M1: sources + entries. Later milestones add buckets, rules, tags, users, etc.

CREATE TABLE sources (
    id          BIGSERIAL PRIMARY KEY,
    org_id      BIGINT,                       -- multi-tenant-ready, unused in v1
    ip          TEXT        NOT NULL DEFAULT '',
    hostname    TEXT        NOT NULL DEFAULT '',
    vendor      TEXT        NOT NULL DEFAULT '',
    zone        TEXT        NOT NULL DEFAULT '',  -- OT/ICS zone
    site        TEXT        NOT NULL DEFAULT '',
    first_seen  TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen   TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (hostname, ip)
);

CREATE TABLE entries (
    id          BIGSERIAL PRIMARY KEY,
    org_id      BIGINT,
    received_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    device_time TIMESTAMPTZ,
    source_id   BIGINT REFERENCES sources(id),
    facility    SMALLINT,
    severity    SMALLINT    NOT NULL DEFAULT 6,   -- RFC5424: 0=emerg .. 7=debug
    app_name    TEXT        NOT NULL DEFAULT '',
    host        TEXT        NOT NULL DEFAULT '',
    msg         TEXT        NOT NULL DEFAULT '',
    structured  JSONB       NOT NULL DEFAULT '{}',
    priority    SMALLINT    NOT NULL DEFAULT 0,
    status      TEXT        NOT NULL DEFAULT 'new',
    assignee_id BIGINT,
    msg_tsv     tsvector GENERATED ALWAYS AS (to_tsvector('simple', msg)) STORED
);

CREATE INDEX entries_received_at_brin ON entries USING BRIN (received_at);
CREATE INDEX entries_structured_gin   ON entries USING GIN (structured);
CREATE INDEX entries_msg_fts          ON entries USING GIN (msg_tsv);
CREATE INDEX entries_source_severity  ON entries (source_id, severity);
CREATE INDEX entries_host             ON entries (host);
