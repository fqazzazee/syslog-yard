import { useState } from "react";
import type { Filters } from "./../types";

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

export default function FilterBar({ filters, onChange }: Props) {
  // Text inputs are local state, applied on Enter/blur so typing doesn't
  // refetch per keystroke.
  const [draft, setDraft] = useState(filters);

  const apply = () => onChange(draft);
  const set = (patch: Partial<Filters>) => setDraft({ ...draft, ...patch });
  const setAndApply = (patch: Partial<Filters>) => {
    const next = { ...draft, ...patch };
    setDraft(next);
    onChange(next);
  };

  return (
    <div className="filterbar">
      <input
        className="search"
        placeholder="Search messages… (full-text)"
        value={draft.q}
        onChange={(e) => set({ q: e.target.value })}
        onKeyDown={(e) => e.key === "Enter" && apply()}
        onBlur={apply}
      />
      <input
        placeholder="host"
        value={draft.host}
        onChange={(e) => set({ host: e.target.value })}
        onKeyDown={(e) => e.key === "Enter" && apply()}
        onBlur={apply}
      />
      <input
        placeholder="app"
        value={draft.app}
        onChange={(e) => set({ app: e.target.value })}
        onKeyDown={(e) => e.key === "Enter" && apply()}
        onBlur={apply}
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
