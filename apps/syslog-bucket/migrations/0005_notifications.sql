-- S9: notifications. A channel is a delivery destination (generic webhook,
-- Slack/Teams incoming webhook, or SMTP email); the `notify` rule action
-- fires matching entries at a channel. notification_log records deliveries so
-- the UI can show "did it fire" and surface errors. Secrets (SMTP password)
-- live in config JSONB and are redacted by the API on read.

CREATE TABLE notification_channels (
    id           BIGSERIAL PRIMARY KEY,
    org_id       BIGINT,
    name         TEXT    NOT NULL UNIQUE,
    kind         TEXT    NOT NULL CHECK (kind IN ('webhook', 'slack', 'smtp')),
    config       JSONB   NOT NULL DEFAULT '{}',
    enabled      BOOLEAN NOT NULL DEFAULT TRUE,
    rate_per_min INT     NOT NULL DEFAULT 30,  -- 0 = unlimited
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE notification_log (
    id         BIGSERIAL PRIMARY KEY,
    channel_id BIGINT REFERENCES notification_channels(id) ON DELETE CASCADE,
    entry_id   BIGINT,
    rule_id    BIGINT,
    status     TEXT NOT NULL,            -- ok | error | dropped
    detail     TEXT NOT NULL DEFAULT '',
    sent_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX notification_log_channel ON notification_log (channel_id, sent_at DESC);
