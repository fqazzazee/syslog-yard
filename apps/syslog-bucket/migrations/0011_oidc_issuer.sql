-- Bind SSO accounts to the issuer that authenticated them: a subject is only
-- unique within one issuer.
--
-- Existing accounts keep a NULL issuer here because the issuer in use may come
-- from the environment, which SQL can't see. The first start after this
-- migration binds them once to the configured issuer
-- (Store.BindLegacyOIDCIssuer). COALESCE keeps those rows unique by subject
-- until then; every subject is already unique, so the index always builds.

ALTER TABLE users ADD COLUMN oidc_issuer TEXT;
ALTER TABLE users DROP CONSTRAINT IF EXISTS users_oidc_subject_key;
CREATE UNIQUE INDEX users_oidc_identity ON users (COALESCE(oidc_issuer, ''), oidc_subject)
    WHERE oidc_subject IS NOT NULL;
