import { useEffect, useState } from "react";
import { Button } from "../../../../shared/web/src/ui";
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
  // On narrow screens only the search box shows until "Filters" opens.
  const [expanded, setExpanded] = useState(false);
  const active = ["host", "app", "severity", "status", "deviceClass"].filter((k) => draft[k as keyof BarFields]).length;
  const setAndApply = (patch: Partial<BarFields>) => {
    const next = { ...draft, ...patch };
    setDraft(next);
    commit(next);
  };

  return (
    <div className={`filterbar${expanded ? " expanded" : ""}`} role="search">
      <input
        className="search"
        type="search"
        aria-label="Search messages"
        title={'Whole words; "quoted phrase", or, -exclude'}
        placeholder={'Search messages — words, "phrase", or, -not'}
        value={draft.q}
        onChange={(e) => set({ q: e.target.value })}
        onKeyDown={(e) => e.key === "Enter" && apply()}
        onBlur={applyIfChanged}
      />
      <Button
        className="filter-toggle"
        icon="tune"
        aria-expanded={expanded}
        onClick={() => setExpanded(!expanded)}
      >
        Filters{active ? ` (${active})` : ""}
      </Button>
      <input
        className="filter-extra"
        aria-label="Host"
        placeholder="host"
        value={draft.host}
        onChange={(e) => set({ host: e.target.value })}
        onKeyDown={(e) => e.key === "Enter" && apply()}
        onBlur={applyIfChanged}
      />
      <input
        className="filter-extra"
        aria-label="App"
        placeholder="app"
        value={draft.app}
        onChange={(e) => set({ app: e.target.value })}
        onKeyDown={(e) => e.key === "Enter" && apply()}
        onBlur={applyIfChanged}
      />
      <select className="filter-extra" aria-label="Severity" value={draft.severity} onChange={(e) => setAndApply({ severity: e.target.value })}>
        {SEVERITY_OPTIONS.map((o) => (
          <option key={o.value} value={o.value}>
            {o.label}
          </option>
        ))}
      </select>
      <select className="filter-extra" aria-label="Status" value={draft.status} onChange={(e) => setAndApply({ status: e.target.value })}>
        {STATUS_OPTIONS.map((o) => (
          <option key={o.value} value={o.value}>
            {o.label}
          </option>
        ))}
      </select>
      <select className="filter-extra" aria-label="Device class" value={draft.deviceClass} onChange={(e) => setAndApply({ deviceClass: e.target.value })}>
        <option value="">Any device</option>
        {DEVICE_CLASSES.map((c) => (
          <option key={c} value={c}>
            {c}
          </option>
        ))}
      </select>
      <select className="filter-extra" aria-label="Time range" value={draft.range} onChange={(e) => setAndApply({ range: e.target.value })}>
        {RANGE_OPTIONS.map((o) => (
          <option key={o.value} value={o.value}>
            {o.label}
          </option>
        ))}
      </select>
    </div>
  );
}
