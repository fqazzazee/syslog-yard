// Built-in About / Help dialog for the syslog-yard suite: who made it, where
// the source lives, what each tool does, a short how-to for the current tool,
// and links to the full docs. Reachable from every top bar (the help button).
// One copy for the whole suite.
import { Dialog } from "./Dialog";
import { Icon } from "./Icon";
import { TOOLS, type ToolId } from "./suite";

const REPO = "https://github.com/fqazzazee/syslog-yard";
const docUrl = (p: string) => `${REPO}/blob/main/${p}`;

const BLURB: Record<ToolId, string> = {
  hose: "generates random-but-realistic syslog traffic at a configurable rate",
  valve: "a visual router/filter built on syslog-ng — graphical IN/OUT ports, filtering, TLS, disk cache",
  bucket: "a multi-user syslog server and triage UI modeled on an email client",
};

const HOWTO: Record<ToolId, { steps: string[]; tip: string }> = {
  hose: {
    steps: [
      "New job → pick a vendor preset (FortiGate, Cisco, Linux …), a destination, and a send rate.",
      "Start the job — the live tail under the jobs (or the Live tail page) shows exactly what is being sent.",
      "Run several jobs at once; “Stop all” halts every running job.",
    ],
    tip: "On the suite network the destination defaults to the valve (syslog-valve:514). Every field stays editable.",
  },
  valve: {
    steps: [
      "Add IN ports (UDP/TCP/TLS), Filter, OUT port, Cache and Notify nodes from the Add menu, then wire them on the canvas.",
      "Filters expose match / else ports — forward critical traffic to the bucket and cache the rest to disk.",
      "Apply compiles the graph to a syslog-ng config, syntax-checks it, swaps atomically, and keeps a one-click rollback under History.",
    ],
    tip: "The live tail shows everything entering each IN port; Export / Import save the whole graph as JSON.",
  },
  bucket: {
    steps: [
      "Pick a bucket (a saved search) in the side navigation; the table is sortable and filterable, with the entry detail beside it.",
      "Rules tag, prioritize, suppress and can Notify a channel at ingest; the ATT&CK matrix maps entries to MITRE techniques.",
      "Manage tags, notification channels and users from the navigation and the account menu, and share buckets per-user.",
    ],
    tip: "Signing in here covers the whole yard — the bucket is the suite’s identity provider. In the log table, j / k or the arrow keys move between rows and Enter opens one.",
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

export function About({ tool, onClose }: { tool: ToolId; onClose: () => void }) {
  const here = TOOLS.find((t) => t.id === tool)!;
  const howto = HOWTO[tool];

  return (
    <Dialog title="syslog-yard" titleIcon={<Icon name="yard" size={22} />} onClose={onClose} className="about">
      <p className="about-tagline">
        One yard, three tools — a self-hosted syslog toolkit: generate → route/filter → store, deployed as plain
        containers under a single compose file.
      </p>

      <dl className="about-meta">
        <div>
          <dt>Author</dt>
          <dd>Fadi Q</dd>
        </div>
        <div>
          <dt>Source</dt>
          <dd>
            <a href={REPO} target="_blank" rel="noopener noreferrer">
              github.com/fqazzazee/syslog-yard
            </a>
          </dd>
        </div>
      </dl>

      <h3>The yard</h3>
      <ul className="about-tools">
        {TOOLS.map((t) => (
          <li key={t.id} className={t.id === tool ? "current" : undefined} data-tool={t.id}>
            <Icon name={t.icon} size={18} />
            <span>
              <b>{t.name}</b>
              {t.id === tool && <span className="about-here">you are here</span>} — {BLURB[t.id]}
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
    </Dialog>
  );
}
