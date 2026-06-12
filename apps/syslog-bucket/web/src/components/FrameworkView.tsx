import { useEffect, useMemo, useState } from "react";
import { fetchMitreSummary, fetchOtSummary } from "./../api";
import type { Filters, Framework, Selection } from "./../types";

interface Props {
  framework: Framework;
  filters: Filters;
  selection: Selection;
  onSelectItem: (fw: string, id: string) => void;
}

// FrameworkView lays a compliance framework out like the ATT&CK matrix: one
// column per group, control/category cells with the count of entries that map
// onto them. Counts are aggregated from the existing per-technique and
// per-OT-alert summaries via the framework's crosswalk — no extra storage.
// Reuses the .mitre-* matrix styling.
export default function FrameworkView({ framework, filters, selection, onSelectItem }: Props) {
  const [mitre, setMitre] = useState<Record<string, number>>({});
  const [ot, setOt] = useState<Record<string, number>>({});
  const [error, setError] = useState<string | null>(null);

  // Counts follow the filter bar but ignore any framework selection so the
  // whole matrix stays populated.
  useEffect(() => {
    const base: Selection =
      selection.kind === "framework" || selection.kind === "frameworkitem" ? { kind: "all" } : selection;
    let stale = false;
    Promise.all([fetchMitreSummary(filters, base), fetchOtSummary(filters, base)])
      .then(([m, o]) => {
        if (stale) return;
        setMitre(m);
        setOt(o);
      })
      .catch((e) => !stale && setError(String(e)));
    return () => {
      stale = true;
    };
  }, [framework.id, filters, selection]);

  const counts = useMemo(() => {
    const out: Record<string, number> = {};
    for (const it of framework.items) {
      let n = 0;
      for (const m of it.mitre ?? []) n += mitre[m] ?? 0;
      for (const o of it.ot ?? []) n += ot[o] ?? 0;
      out[it.id] = n;
    }
    return out;
  }, [framework, mitre, ot]);

  const byGroup = useMemo(
    () =>
      framework.groups.map((g) => ({
        group: g,
        items: framework.items
          .filter((it) => it.group === g.id)
          .map((it) => ({ ...it, count: counts[it.id] ?? 0 }))
          .sort((a, b) => b.count - a.count || a.name.localeCompare(b.name)),
      })),
    [framework, counts],
  );

  const total = Object.values(counts).reduce((a, b) => a + b, 0);

  if (error) return <div className="error">{error}</div>;

  return (
    <div className="mitre-view">
      <p className="mitre-intro">
        {framework.name} — {framework.desc}. {total.toLocaleString()} mapped hits in this window (crosswalked from
        ATT&CK techniques &amp; OT alerts). Click a cell to see the entries.
      </p>
      <div className="mitre-matrix">
        {byGroup.map(({ group, items }) => (
          <div key={group.id} className="mitre-col">
            <div className="mitre-tactic" title={group.name}>
              {group.name}
            </div>
            {items.map((it) => (
              <button
                key={it.id}
                className={`mitre-tech${it.count > 0 ? " hit" : ""}`}
                title={it.name}
                onClick={() => onSelectItem(framework.id, it.id)}
              >
                <span className="mitre-tech-name">{it.name}</span>
                <span className="mitre-tech-meta">
                  <span className="mitre-tech-id">{it.id}</span>
                  {it.count > 0 && <span className="mitre-count">{it.count}</span>}
                </span>
              </button>
            ))}
          </div>
        ))}
      </div>
    </div>
  );
}
