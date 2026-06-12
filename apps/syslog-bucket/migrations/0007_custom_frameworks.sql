-- Site-defined "custom org labels": compliance/standards frameworks an operator
-- adds at runtime. Each is stored as one frameworks.Framework document (groups +
-- items, each item crosswalking to mitre techniques / ot codes / device classes).
-- They are merged with the built-in catalogs by the API layer; the synthetic id
-- presented to the UI is "custom-<id>".

CREATE TABLE custom_frameworks (
    id         BIGSERIAL PRIMARY KEY,
    doc        JSONB       NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
