import { useState } from "react";
import type { Cond, Tag } from "./../types";
import { Icon } from "./Icon";

// The builder edits the common shape — a flat AND of leaf conditions. Trees
// with any/not nesting fall back to a raw JSON editor so nothing the backend
// supports is unreachable.

type Row =
  | { kind: "text"; text: string }
  | { kind: "tag"; tagId: number }
  | { kind: "window"; minutes: number }
  | { kind: "field"; field: string; op: string; value: string };

interface FieldDef {
  value: string;
  label: string;
  numeric?: boolean;
  ops: string[];
}

const STR_OPS = ["contains", "eq", "ne", "prefix"];
const NUM_OPS = ["eq", "ne", "lt", "lte", "gt", "gte"];

const FIELD_DEFS: FieldDef[] = [
  { value: "host", label: "Host", ops: STR_OPS },
  { value: "app_name", label: "App", ops: STR_OPS },
  { value: "msg", label: "Message", ops: STR_OPS },
  { value: "status", label: "Status", ops: ["eq", "ne"] },
  { value: "severity", label: "Severity", numeric: true, ops: ["lte", ...NUM_OPS] },
  { value: "facility", label: "Facility", numeric: true, ops: NUM_OPS },
  { value: "priority", label: "Priority", numeric: true, ops: NUM_OPS },
];

const OP_LABELS: Record<string, string> = {
  contains: "contains",
  eq: "=",
  ne: "≠",
  prefix: "starts with",
  lt: "<",
  lte: "≤",
  gt: ">",
  gte: "≥",
};

function isNumeric(field: string): boolean {
  return FIELD_DEFS.find((d) => d.value === field)?.numeric ?? false;
}

function leafToRow(c: Cond): Row | null {
  const keys = Object.keys(c).filter((k) => c[k as keyof Cond] !== undefined);
  if (keys.length === 0) return null;
  if (c.text) return { kind: "text", text: c.text };
  if (c.tag_id) return { kind: "tag", tagId: c.tag_id };
  if (c.last_seconds) return { kind: "window", minutes: Math.round(c.last_seconds / 60) };
  if (c.field && keys.every((k) => ["field", "op", "value"].includes(k))) {
    return { kind: "field", field: c.field, op: c.op ?? "eq", value: String(c.value ?? "") };
  }
  return null;
}

export function condToRows(c: Cond): Row[] | null {
  if (!c || Object.keys(c).length === 0) return [];
  if (c.all) {
    const rows: Row[] = [];
    for (const sub of c.all) {
      const row = leafToRow(sub);
      if (!row) return null;
      rows.push(row);
    }
    return rows;
  }
  const single = leafToRow(c);
  return single ? [single] : null;
}

export function rowsToCond(rows: Row[]): Cond {
  const leaves = rows.map((r): Cond => {
    switch (r.kind) {
      case "text":
        return { text: r.text };
      case "tag":
        return { tag_id: r.tagId };
      case "window":
        return { last_seconds: r.minutes * 60 };
      case "field":
        return {
          field: r.field,
          op: r.op,
          value: isNumeric(r.field) ? Number(r.value) : r.value,
        };
    }
  });
  if (leaves.length === 0) return {};
  if (leaves.length === 1) return leaves[0];
  return { all: leaves };
}

interface Props {
  value: Cond;
  onChange: (c: Cond) => void;
  tags: Tag[];
}

export default function ConditionBuilder({ value, onChange, tags }: Props) {
  const initialRows = condToRows(value);
  const [jsonMode, setJsonMode] = useState(initialRows === null);
  const [jsonDraft, setJsonDraft] = useState(() => JSON.stringify(value, null, 2));
  const [jsonError, setJsonError] = useState<string | null>(null);

  const rows = condToRows(value) ?? [];
  const setRows = (next: Row[]) => onChange(rowsToCond(next));
  const patchRow = (i: number, patch: Partial<Row>) =>
    setRows(rows.map((r, j) => (j === i ? ({ ...r, ...patch } as Row) : r)));

  if (jsonMode) {
    return (
      <div className="condbuilder">
        <textarea
          className="cond-json"
          rows={8}
          value={jsonDraft}
          onChange={(e) => setJsonDraft(e.target.value)}
          onBlur={() => {
            try {
              onChange(JSON.parse(jsonDraft) as Cond);
              setJsonError(null);
            } catch (err) {
              setJsonError(String(err));
            }
          }}
        />
        {jsonError && <div className="error">{jsonError}</div>}
        <button
          type="button"
          className="linkish"
          disabled={condToRows(value) === null}
          onClick={() => setJsonMode(false)}
        >
          Switch to builder
        </button>
      </div>
    );
  }

  return (
    <div className="condbuilder">
      {rows.length === 0 && <p className="hint">No conditions: matches every entry.</p>}
      {rows.map((row, i) => (
        <div className="cond-row" key={i}>
          <select
            value={row.kind}
            onChange={(e) => {
              const kind = e.target.value as Row["kind"];
              const fresh: Row =
                kind === "text"
                  ? { kind, text: "" }
                  : kind === "tag"
                    ? { kind, tagId: tags[0]?.id ?? 0 }
                    : kind === "window"
                      ? { kind, minutes: 60 }
                      : { kind, field: "host", op: "contains", value: "" };
              setRows(rows.map((r, j) => (j === i ? fresh : r)));
            }}
          >
            <option value="field">Field</option>
            <option value="text">Full text</option>
            <option value="tag">Has tag</option>
            <option value="window">Time window</option>
          </select>

          {row.kind === "field" && (
            <>
              <select
                value={FIELD_DEFS.some((d) => d.value === row.field) ? row.field : "custom"}
                onChange={(e) => {
                  const v = e.target.value;
                  patchRow(i, v === "custom" ? { field: "structured." } : { field: v, op: "contains" });
                }}
              >
                {FIELD_DEFS.map((d) => (
                  <option key={d.value} value={d.value}>
                    {d.label}
                  </option>
                ))}
                <option value="custom">structured…</option>
              </select>
              {!FIELD_DEFS.some((d) => d.value === row.field) && (
                <input
                  placeholder="structured.key"
                  value={row.field}
                  onChange={(e) => patchRow(i, { field: e.target.value })}
                />
              )}
              <select value={row.op} onChange={(e) => patchRow(i, { op: e.target.value })}>
                {(FIELD_DEFS.find((d) => d.value === row.field)?.ops ?? STR_OPS).map((op) => (
                  <option key={op} value={op}>
                    {OP_LABELS[op]}
                  </option>
                ))}
              </select>
              <input
                className="cond-value"
                placeholder="value"
                value={row.value}
                onChange={(e) => patchRow(i, { value: e.target.value })}
              />
            </>
          )}

          {row.kind === "text" && (
            <input
              className="cond-value"
              placeholder="words to search for"
              value={row.text}
              onChange={(e) => patchRow(i, { text: e.target.value })}
            />
          )}

          {row.kind === "tag" && (
            <select value={row.tagId} onChange={(e) => patchRow(i, { tagId: Number(e.target.value) })}>
              {tags.map((t) => (
                <option key={t.id} value={t.id}>
                  {t.name}
                </option>
              ))}
            </select>
          )}

          {row.kind === "window" && (
            <>
              <span>last</span>
              <input
                type="number"
                min={1}
                value={row.minutes}
                onChange={(e) => patchRow(i, { minutes: Number(e.target.value) })}
              />
              <span>minutes</span>
            </>
          )}

          <button type="button" className="linkish" onClick={() => setRows(rows.filter((_, j) => j !== i))}>
            <Icon name="close" size={14} />
          </button>
        </div>
      ))}

      <div className="cond-actions">
        <button
          type="button"
          className="linkish"
          onClick={() => setRows([...rows, { kind: "field", field: "host", op: "contains", value: "" }])}
        >
          + condition
        </button>
        <button
          type="button"
          className="linkish"
          onClick={() => {
            setJsonDraft(JSON.stringify(value, null, 2));
            setJsonError(null);
            setJsonMode(true);
          }}
        >
          Edit as JSON
        </button>
      </div>
    </div>
  );
}
