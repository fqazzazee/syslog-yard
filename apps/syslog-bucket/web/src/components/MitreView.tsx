import { useEffect, useMemo, useState } from "react";
import { fetchCoverage, fetchMitre, fetchMitreSummary } from "./../api";
import type { Coverage, Filters, MitreCatalog, Selection } from "./../types";
import { CoverageBanner } from "./CoverageBanner";

interface Props {
  filters: Filters;
  selection: Selection; // the active filter context for the counts
  onSelectTechnique: (id: string) => void;
}

// MitreView lays the mapped techniques out as an ATT&CK matrix: one column per
// tactic (in kill-chain order), techniques sorted by how many entries matched
// them in the current time window. Clicking a technique opens its entries.
export default function MitreView({ filters, selection, onSelectTechnique }: Props) {
  const [catalog, setCatalog] = useState<MitreCatalog | null>(null);
  const [counts, setCounts] = useState<Record<string, number>>({});
  const [coverage, setCoverage] = useState<Coverage | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetchMitre().then(setCatalog).catch((e) => setError(String(e)));
  }, []);

  // Counts follow the filter bar (time range, host, …) but ignore any
  // technique/tactic selection so the whole matrix stays populated.
  useEffect(() => {
    const base: Selection = selection.kind === "technique" || selection.kind === "mitre" ? { kind: "all" } : selection;
    let stale = false;
    fetchMitreSummary(filters, base)
      .then((c) => !stale && setCounts(c))
      .catch((e) => !stale && setError(String(e)));
    fetchCoverage(filters, base)
      .then((c) => !stale && setCoverage(c))
      .catch(() => {});
    return () => {
      stale = true;
    };
  }, [filters, selection]);

  const byTactic = useMemo(() => {
    if (!catalog) return [];
    return catalog.tactics.map((tac) => {
      const techs = catalog.techniques
        .filter((t) => t.tactics.includes(tac.short))
        .map((t) => ({ ...t, count: counts[t.id] ?? 0 }))
        .sort((a, b) => b.count - a.count || a.id.localeCompare(b.id));
      return { tactic: tac, techniques: techs };
    });
  }, [catalog, counts]);

  const total = Object.values(counts).reduce((a, b) => a + b, 0);

  if (error) return <div className="error">{error}</div>;
  if (!catalog) return <div className="mitre-view empty">Loading ATT&CK matrix…</div>;

  return (
    <div className="mitre-view">
      <p className="mitre-intro">
        Events mapped to MITRE ATT&CK at ingest — {total.toLocaleString()} technique hits in this window.
        Click a technique to see the entries.
      </p>
      {coverage && <CoverageBanner covered={coverage.mitre} total={coverage.total} noun="mapped to ATT&CK" />}
      <div className="mitre-matrix">
        {byTactic.map(({ tactic, techniques }) => (
          <div key={tactic.id} className="mitre-col">
            <div className="mitre-tactic" title={tactic.id}>
              {tactic.name}
            </div>
            {techniques.map((t) => (
              <button
                key={t.id}
                className={`mitre-tech${t.count > 0 ? " hit" : ""}`}
                title={`${t.id} — ${t.name}`}
                onClick={() => onSelectTechnique(t.id)}
              >
                <span className="mitre-tech-name">{t.name}</span>
                <span className="mitre-tech-meta">
                  <span className="mitre-tech-id">{t.id}</span>
                  {t.count > 0 && <span className="mitre-count">{t.count}</span>}
                </span>
              </button>
            ))}
          </div>
        ))}
      </div>
    </div>
  );
}
