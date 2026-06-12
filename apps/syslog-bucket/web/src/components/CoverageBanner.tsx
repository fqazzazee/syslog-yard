// CoverageBanner visualises the "unclassified" gap for a mapping: how many of
// the events in the current window the mapping covers, and how many it doesn't.
// covered/total come from /api/coverage.
export function CoverageBanner({ covered, total, noun }: { covered: number; total: number; noun: string }) {
  if (total === 0) return null;
  const gap = Math.max(0, total - covered);
  const pct = Math.round((covered / total) * 100);
  return (
    <div className="coverage-banner" title={`${covered.toLocaleString()} of ${total.toLocaleString()} ${noun}`}>
      <span className="coverage-bar">
        <span className="coverage-fill" style={{ width: `${pct}%` }} />
      </span>
      <span className="coverage-text">
        {pct}% {noun} · <strong>{gap.toLocaleString()}</strong> unclassified of {total.toLocaleString()}
      </span>
    </div>
  );
}
