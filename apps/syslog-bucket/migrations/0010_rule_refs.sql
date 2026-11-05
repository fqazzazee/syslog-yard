-- The tags and notification channels that ENABLED rules' actions point at,
-- one row per (rule, target). rules.actions stays the source of truth for
-- what a rule does; the store rewrites these rows in the same transaction as
-- every rule write, so the foreign keys let Postgres itself:
--
--   * refuse to delete a tag or channel an enabled rule still uses, and
--   * refuse to save or enable a rule that points at one that doesn't exist,
--
-- with no window between a check and the write. Disabled rules have no rows,
-- so they never block a delete; enabling one again re-checks its targets.

CREATE TABLE rule_refs (
    rule_id    BIGINT NOT NULL REFERENCES rules (id) ON DELETE CASCADE,
    tag_id     BIGINT REFERENCES tags (id),
    channel_id BIGINT REFERENCES notification_channels (id),
    CHECK ((tag_id IS NULL) <> (channel_id IS NULL))
);

CREATE UNIQUE INDEX rule_refs_rule_tag ON rule_refs (rule_id, tag_id) WHERE tag_id IS NOT NULL;
CREATE UNIQUE INDEX rule_refs_rule_channel ON rule_refs (rule_id, channel_id) WHERE channel_id IS NOT NULL;
-- Deleting a tag or channel looks its referencing rows up by target.
CREATE INDEX rule_refs_tag ON rule_refs (tag_id) WHERE tag_id IS NOT NULL;
CREATE INDEX rule_refs_channel ON rule_refs (channel_id) WHERE channel_id IS NOT NULL;

-- Backfill from the enabled rules. A reference to something already gone is
-- skipped rather than failing the upgrade; the API refuses to save such a
-- rule again until the action is fixed.
INSERT INTO rule_refs (rule_id, tag_id)
SELECT DISTINCT r.id, (a->>'tag_id')::bigint
FROM rules r, jsonb_array_elements(r.actions) a
WHERE r.enabled AND a->>'type' = 'tag'
  AND EXISTS (SELECT 1 FROM tags t WHERE t.id = (a->>'tag_id')::bigint);

INSERT INTO rule_refs (rule_id, channel_id)
SELECT DISTINCT r.id, (a->>'channel_id')::bigint
FROM rules r, jsonb_array_elements(r.actions) a
WHERE r.enabled AND a->>'type' = 'notify'
  AND EXISTS (SELECT 1 FROM notification_channels c WHERE c.id = (a->>'channel_id')::bigint);
