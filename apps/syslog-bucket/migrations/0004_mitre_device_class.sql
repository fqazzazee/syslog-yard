-- MITRE ATT&CK technique tagging + device classification. Techniques are
-- stamped at ingest by internal/mitre (an array of IDs like {T1110,T1190});
-- device_class is the coarse class from internal/classify. Both are set on
-- the entry before insert, so existing rows keep the defaults.

ALTER TABLE entries ADD COLUMN mitre        TEXT[] NOT NULL DEFAULT '{}';
ALTER TABLE entries ADD COLUMN device_class TEXT   NOT NULL DEFAULT '';

-- GIN for "entries carrying technique X" (array containment); btree for
-- grouping/sorting by class.
CREATE INDEX entries_mitre_gin    ON entries USING GIN (mitre);
CREATE INDEX entries_device_class ON entries (device_class);
