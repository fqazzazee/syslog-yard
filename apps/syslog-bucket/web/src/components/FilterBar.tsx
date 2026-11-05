import { useEffect, useState } from "react";
import type { Filters } from "./../types";
import { DEVICE_CLASSES } from "./../types";

const SEVERITY_OPTIONS = [
  { value: "", label: "Any severity" },
  { value: "0", label: "Emergency" },
  { value: "1", label: "Alert+" },
  { value: "2", label: "Critical+" },
  { value: "3", label: "Error+" },
  { value: "4", label: "Warning+" },
  { value: "5", label: "Notice+" },
  { value: "6", label: "Info+" },
  { value: "7", label: "Debug+" },
];

const STATUS_OPTIONS = [
  { value: "", label: "Any status" },
  { value: "new", label: "New" },
  { value: "reviewing", label: "Reviewing" },
  { value: "resolved", label: "Resolved" },
];

const RANGE_OPTIONS = [
  { value: "15", label: "Last 15 min" },
  { value: "60", label: "Last hour" },
  { value: "1440", label: "Last 24 h" },
  { value: "10080", label: "Last 7 days" },
  { value: "", label: "All time" },
];

interface Props {
  filters: Filters;
  onChange: (f: Filters) => void;
}

// The fields this bar edits. Sort/direction live in the same Filters object
// but are owned by the table headers, so they are never part of the draft.
type BarFields = Pick<Filters, "q" | "host" | "app" | "severity" | "status" | "deviceClass" | "range">;
const BAR_KEYS: (keyof BarFields)[] = ["q", "host", "app", "severity", "status", "deviceClass", "range"];

function barFields(f: Filters): BarFields {
  return { q: f.q, host: f.host, app: f.app, severity: f.severity, status: f.status, deviceClass: f.deviceClass, range: f.range };
}

export default function FilterBar({ filters, onChange }: Props) {
  // Text inputs are local state, applied on Enter/blur so typing doesn't
  // refetch per keystroke.
  const [draft, setDraft] = useState<BarFields>(() => barFields(filters));

  // Follow external changes to the bar's own fields (e.g. a reset).
  const external = barFields(filters);
  const externalKey = BAR_KEYS.map((k) => external[k]).join("\u0000");
  useEffect(() => {
    setDraft(barFields(filters));
  }, [externalKey]);

  // Merge over the current filters so a column sort chosen since the last
  // apply is kept. A blur that changed nothing is skipped (it would otherwise
  // refetch on every focus change); Enter always re-runs the query.
  const commit = (next: BarFields, force = true) => {
    if (!force && BAR_KEYS.every((k) => next[k] === filters[k])) return;
    onChange({ ...filters, ...next });
  };
  const apply = () => commit(draft);
  const applyIfChanged = () => commit(draft, false);
  const set = (patch: Partial<BarFields>) => setDraft({ ...draft, ...patch });
  const setAndApply = (patch: Partial<BarFields>) => {
    const next = { ...draft, ...patch };
    setDraft(next);
    commit(next);
  };

  return (
    <div className="filterbar">
      <input
        className="search"
        placeholder="Search messages… (full-text)"
        value={draft.q}
        onChange={(e) => set({ q: e.target.value })}
        onKeyDown={(e) => e.key === "Enter" && apply()}
        onBlur={applyIfChanged}
      />
      <input
        placeholder="host"
        value={draft.host}
        onChange={(e) => set({ host: e.target.value })}
        onKeyDown={(e) => e.key === "Enter" && apply()}
        onBlur={applyIfChanged}
      />
      <input
        placeholder="app"
        value={draft.app}
        onChange={(e) => set({ app: e.target.value })}
        onKeyDown={(e) => e.key === "Enter" && apply()}
        onBlur={applyIfChanged}
      />
      <select value={draft.severity} onChange={(e) => setAndApply({ severity: e.target.value })}>
        {SEVERITY_OPTIONS.map((o) => (
          <option key={o.value} value={o.value}>
            {o.label}
          </option>
        ))}
      </select>
      <select value={draft.status} onChange={(e) => setAndApply({ status: e.target.value })}>
        {STATUS_OPTIONS.map((o) => (
          <option key={o.value} value={o.value}>
            {o.label}
          </option>
        ))}
      </select>
      <select value={draft.deviceClass} onChange={(e) => setAndApply({ deviceClass: e.target.value })}>
        <option value="">Any device</option>
        {DEVICE_CLASSES.map((c) => (
          <option key={c} value={c}>
            {c}
          </option>
        ))}
      </select>
      <select value={draft.range} onChange={(e) => setAndApply({ range: e.target.value })}>
        {RANGE_OPTIONS.map((o) => (
          <option key={o.value} value={o.value}>
            {o.label}
          </option>
        ))}
      </select>
    </div>
  );
}
