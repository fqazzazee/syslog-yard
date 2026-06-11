import { useEffect, useMemo, useState } from "react";
import { fetchOt, fetchOtSummary } from "./../api";
import type { Filters, OTCatalog, Selection } from "./../types";

interface Props {
  filters: Filters;
  selection: Selection; // the active filter context for the counts
  onSelectAlert: (id: string) => void;
}

// OTView lays the Claroty-style OT alerts out like the ATT&CK matrix: one
// column per category (Security, Integrity), alert types sorted by how many
// entries matched them in the current window. Clicking an alert opens its
// entries. It reuses the .mitre-* matrix styling for a consistent look.
export default function OTView({ filters, selection, onSelectAlert }: Props) {
  const [catalog, setCatalog] = useState<OTCatalog | null>(null);
  const [counts, setCounts] = useState<Record<string, number>>({});
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetchOt().then(setCatalog).catch((e) => setError(String(e)));
  }, []);

  // Counts follow the filter bar but ignore any OT selection so the whole
  // matrix stays populated.
  useEffect(() => {
    const base: Selection = selection.kind === "otalert" || selection.kind === "ot" ? { kind: "all" } : selection;
    let stale = false;
    fetchOtSummary(filters, base)
      .then((c) => !stale && setCounts(c))
      .catch((e) => !stale && setError(String(e)));
    return () => {
      stale = true;
    };
  }, [filters, selection]);

  const byCategory = useMemo(() => {
    if (!catalog) return [];
    return catalog.categories.map((cat) => {
      const alerts = catalog.alert_types
        .filter((a) => a.categories.includes(cat.short))
        .map((a) => ({ ...a, count: counts[a.id] ?? 0 }))
        .sort((x, y) => y.count - x.count || x.name.localeCompare(y.name));
      return { category: cat, alerts };
    });
  }, [catalog, counts]);

  const total = Object.values(counts).reduce((a, b) => a + b, 0);

  if (error) return <div className="error">{error}</div>;
  if (!catalog) return <div className="mitre-view empty">Loading OT alerts…</div>;

  return (
    <div className="mitre-view">
      <p className="mitre-intro">
        OT/ICS events mapped to Claroty-style alert types at ingest — {total.toLocaleString()} alerts in this window
        (CTD &amp; xDome). Click an alert type to see the entries.
      </p>
      <div className="mitre-matrix ot-matrix">
        {byCategory.map(({ category, alerts }) => (
          <div key={category.id} className="mitre-col">
            <div className={`mitre-tactic ot-cat ot-${category.short}`} title={category.name}>
              {category.name}
            </div>
            {alerts.map((a) => (
              <button
                key={a.id}
                className={`mitre-tech${a.count > 0 ? " hit" : ""}`}
                title={`${a.id} — ${a.name}`}
                onClick={() => onSelectAlert(a.id)}
              >
                <span className="mitre-tech-name">{a.name}</span>
                <span className="mitre-tech-meta">
                  <span className="mitre-tech-id">{a.id}</span>
                  {a.count > 0 && <span className="mitre-count">{a.count}</span>}
                </span>
              </button>
            ))}
          </div>
        ))}
      </div>
    </div>
  );
}
