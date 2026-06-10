// Cross-tool nav for the syslog-yard suite. Link values come from the
// deployment via /api/hints (linkHose / linkValve / linkBucket); each is a
// full URL or a bare port. Renders nothing when running standalone.
const TOOLS = [
  { id: "hose", key: "linkHose", icon: "⟫⟫", label: "hose" },
  { id: "valve", key: "linkValve", icon: "⊶", label: "valve" },
  { id: "bucket", key: "linkBucket", icon: "▣", label: "bucket" },
] as const;

export type ToolId = (typeof TOOLS)[number]["id"];

// A bare port resolves against the host the browser is already on, so the
// default compose links work from localhost and over the LAN alike.
function resolve(link: string): string {
  if (/^\d+$/.test(link)) return `${location.protocol}//${location.hostname}:${link}/`;
  return link;
}

export function YardNav(props: { links: Record<string, string>; current: ToolId }) {
  const others = TOOLS.filter((t) => t.id !== props.current && props.links[t.key]);
  if (others.length === 0) return null;
  return (
    <nav className="yard-nav" aria-label="syslog-yard tools">
      <span className="yard-nav-label">yard</span>
      {TOOLS.map((t) =>
        t.id === props.current ? (
          <span key={t.id} className="yard-link current" title="you are here">
            {t.icon} {t.label}
          </span>
        ) : props.links[t.key] ? (
          <a key={t.id} className="yard-link" href={resolve(props.links[t.key])}>
            {t.icon} {t.label}
          </a>
        ) : null,
      )}
    </nav>
  );
}
