// Built-in About / Help overlay for the syslog-yard suite: who made it, where
// the source lives, what each tool does, a short how-to for the current tool,
// and links to the full docs. Reachable from every top bar (the help button).
//
// Duplicated verbatim in syslog-hose, syslog-valve and syslog-bucket — keep the
// three copies in sync (like AccountMenu / YardNav / Icon).
import { useEffect } from "react";
import { Icon, type IconName } from "./Icon";

const REPO = "https://github.com/fqazzazee/syslog-yard";
const docUrl = (p: string) => `${REPO}/blob/main/${p}`;

type Tool = "hose" | "valve" | "bucket";

const TOOLS: { id: Tool; icon: IconName; name: string; blurb: string }[] = [
  { id: "hose", icon: "water_drop", name: "syslog-hose", blurb: "generates random-but-realistic syslog traffic at a configurable rate" },
  { id: "valve", icon: "valve", name: "syslog-valve", blurb: "a visual router/filter built on syslog-ng — graphical IN/OUT ports, filtering, TLS, disk cache" },
  { id: "bucket", icon: "inbox", name: "syslog-bucket", blurb: "a multi-user syslog server and triage UI modeled on an email client" },
];

const HOWTO: Record<Tool, { steps: string[]; tip: string }> = {
  hose: {
    steps: [
      "New job → pick a vendor preset (FortiGate, Cisco, Linux …), a destination, and a send rate.",
      "Start the job — the live tail at the bottom shows exactly what is being sent.",
      "Run several jobs at once; “Stop all” halts every running job.",
    ],
    tip: "On the suite network the destination defaults to the valve (syslog-valve:514). Every field stays editable.",
  },
  valve: {
    steps: [
      "Add IN ports (UDP/TCP/TLS), Filter, Forward, Cache and Notify nodes from the toolbar, then wire them on the canvas.",
      "Filters expose match / else ports — forward critical traffic to the bucket and cache the rest to disk.",
      "Apply compiles the graph to a syslog-ng config, syntax-checks it, swaps atomically, and keeps a one-click rollback.",
    ],
    tip: "The live tail shows everything entering each IN port; Export / Import save the whole graph as JSON.",
  },
  bucket: {
    steps: [
      "Pick a bucket (a saved search) on the left; the table is sortable and filterable in a 3-pane, email-style layout.",
      "Rules tag, prioritize, suppress and can Notify a channel at ingest; the ATT&CK matrix maps entries to MITRE techniques.",
      "Manage tags, notification channels and users from the sidebar, and share buckets per-user.",
    ],
    tip: "Signing in here covers the whole yard — the bucket is the suite’s identity provider.",
  },
};

const DOCS: { label: string; path: string }[] = [
  { label: "README — quick start & the demo loop", path: "README.md" },
  { label: "Authentication, roles, OIDC & sharing", path: "docs/AUTH.md" },
  { label: "MITRE ATT&CK, sorting & device class", path: "docs/MITRE.md" },
  { label: "Notifications (webhook / Slack-Teams / SMTP)", path: "docs/NOTIFICATIONS.md" },
  { label: "Security: threat model & hardening", path: "docs/SECURITY.md" },
  { label: "External NAS shares (NFS / CIFS)", path: "docs/SHARES.md" },
];

export function About({ tool, onClose }: { tool: Tool; onClose: () => void }) {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [onClose]);

  const here = TOOLS.find((t) => t.id === tool)!;
  const howto = HOWTO[tool];

  return (
    <div className="about-backdrop" onClick={onClose}>
      <div className="about-modal" role="dialog" aria-label="About syslog-yard" onClick={(e) => e.stopPropagation()}>
        <div className="about-head">
          <h2>
            <Icon name="yard" size={22} /> syslog-yard
          </h2>
          <button className="about-close" title="Close" onClick={onClose}>
            <Icon name="close" size={18} />
          </button>
        </div>
        <p className="about-tagline">
          One yard, three tools — an open-source, self-hosted syslog toolkit: generate → route/filter → store, deployed as
          plain containers under a single compose file.
        </p>

        <div className="about-meta">
          <span>
            <span className="about-k">Author</span> Fadi Q
          </span>
          <span>
            <span className="about-k">Source</span>{" "}
            <a href={REPO} target="_blank" rel="noopener noreferrer">
              github.com/fqazzazee/syslog-yard
            </a>
          </span>
        </div>

        <h3>The yard</h3>
        <ul className="about-tools">
          {TOOLS.map((t) => (
            <li key={t.id} className={t.id === tool ? "current" : undefined}>
              <Icon name={t.icon} size={18} />
              <span>
                <b>{t.name}</b>
                {t.id === tool && <span className="about-here">you are here</span>} — {t.blurb}
              </span>
            </li>
          ))}
        </ul>

        <h3>
          <Icon name={here.icon} size={16} /> Using {here.name}
        </h3>
        <ol className="about-steps">
          {howto.steps.map((s, i) => (
            <li key={i}>{s}</li>
          ))}
        </ol>
        <p className="about-tip">
          <Icon name="info" size={15} /> {howto.tip}
        </p>

        <h3>
          <Icon name="menu_book" size={16} /> Documentation
        </h3>
        <ul className="about-docs">
          {DOCS.map((d) => (
            <li key={d.path}>
              <a href={docUrl(d.path)} target="_blank" rel="noopener noreferrer">
                {d.label}
              </a>
            </li>
          ))}
        </ul>
        <p className="about-foot">The full guides also ship in the repository’s docs/ folder.</p>
      </div>
    </div>
  );
}
