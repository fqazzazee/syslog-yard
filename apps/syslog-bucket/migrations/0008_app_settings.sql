-- Runtime, admin-editable settings that used to be startup-only environment
-- variables: the OIDC identity-provider config and the session idle timeout.
-- One JSON document per key ("oidc", "session"). The API layer treats a
-- present row as authoritative and falls back to the BUCKET_* env vars only
-- when the row is absent.

CREATE TABLE app_settings (
    key        TEXT PRIMARY KEY,
    value      JSONB       NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
