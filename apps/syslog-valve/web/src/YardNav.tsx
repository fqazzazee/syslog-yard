// Cross-tool nav for the syslog-yard suite. Link values come from the
// deployment via /api/hints (linkHose / linkValve / linkBucket); each is a
// full URL or a bare port. Renders nothing when running standalone.
//
// Duplicated verbatim in syslog-hose, syslog-valve and syslog-bucket — keep the
// three copies in sync (like AccountMenu / Icon).
import { Icon, type IconName } from "./Icon";

type Tool = { id: ToolId; key: string; icon: IconName; label: string };

// Brand marks (Material Symbols): garden hose → water_drop, valve → valve,
// bucket (email-style triage) → inbox; the suite itself is the yard.
const TOOLS: readonly Tool[] = [
  { id: "hose", key: "linkHose", icon: "water_drop", label: "hose" },
  { id: "valve", key: "linkValve", icon: "valve", label: "valve" },
  { id: "bucket", key: "linkBucket", icon: "inbox", label: "bucket" },
];

export type ToolId = "hose" | "valve" | "bucket";

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
      <span className="yard-nav-label">
        <Icon name="yard" size={13} /> yard
      </span>
      {TOOLS.map((t) =>
        t.id === props.current ? (
          <span key={t.id} className="yard-link current" title="you are here">
            <Icon name={t.icon} size={15} /> {t.label}
          </span>
        ) : props.links[t.key] ? (
          <a key={t.id} className="yard-link" href={resolve(props.links[t.key])}>
            <Icon name={t.icon} size={15} /> {t.label}
          </a>
        ) : null,
      )}
    </nav>
  );
}
