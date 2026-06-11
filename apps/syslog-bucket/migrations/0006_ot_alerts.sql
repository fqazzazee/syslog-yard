-- Claroty-style OT/ICS alert classification. Alert-type codes (like
-- {CL-KT,CL-BASE}) are stamped at ingest by internal/otmap from the Claroty
-- CEF the OT sensors (CTD / xDome) emit. Parallels the mitre column: set on
-- the entry before insert, so existing rows keep the default.

ALTER TABLE entries ADD COLUMN ot TEXT[] NOT NULL DEFAULT '{}';

-- GIN for "entries carrying OT alert X" (array containment), as for mitre.
CREATE INDEX entries_ot_gin ON entries USING GIN (ot);
