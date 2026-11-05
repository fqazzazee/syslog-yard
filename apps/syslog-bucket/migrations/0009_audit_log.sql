-- Audit log: who changed what, from where, and whether it worked. Covers
-- sign-ins, account and settings changes, rule/bucket/tag/channel/framework
-- edits and entry triage. Rows are append-only; the bucket prunes rows older
-- than BUCKET_AUDIT_RETENTION_DAYS (default 180).
--
-- actor_id has no foreign key on purpose: a row must outlive the account it
-- names, so actor_name keeps a snapshot of the username at the time. For a
-- failed sign-in actor_id is NULL and actor_name is the username tried.

CREATE TABLE audit_log (
    id          BIGSERIAL   PRIMARY KEY,
    at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    actor_id    BIGINT,
    actor_name  TEXT        NOT NULL DEFAULT '',
    actor_ip    TEXT        NOT NULL DEFAULT '',
    action      TEXT        NOT NULL,
    target_type TEXT        NOT NULL DEFAULT '',
    target_id   TEXT        NOT NULL DEFAULT '',
    summary     JSONB       NOT NULL DEFAULT '{}',
    success     BOOLEAN     NOT NULL DEFAULT true
);

-- Newest-first paging (the viewer's cursor is (at, id)) and the retention
-- prune both walk this one.
CREATE INDEX audit_log_at_idx ON audit_log (at DESC, id DESC);
-- "What did this person do": by account, and by name for failed sign-ins
-- and deleted accounts.
CREATE INDEX audit_log_actor_idx ON audit_log (actor_id, at DESC);
CREATE INDEX audit_log_actor_name_idx ON audit_log (lower(actor_name), at DESC);
