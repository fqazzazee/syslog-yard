// The syslog-yard suite map: the three tools, their sections, and how to
// link to a section of any of them. The app shell renders its tool switcher
// and side navigation from this, so every tool lists the same structure.
//
// Each tool serves its own SPA on its own port. Cross-tool links come from
// the deployment via each app's GET /api/hints (linkHose / linkValve /
// linkBucket: a full URL or a bare port); sections are hash deep links
// (#/<section>[/<param>…]) that every app accepts.
import type { IconName } from "./Icon";

export type ToolId = "hose" | "valve" | "bucket";

export interface Section {
  id: string;
  label: string;
  icon: IconName;
}

export interface ToolDef {
  id: ToolId;
  name: string; // product name, e.g. "syslog-hose"
  label: string; // short label in the switcher
  tagline: string;
  icon: IconName;
  linkKey: string; // /api/hints key carrying this tool's base URL
  sections: Section[];
}

// Pipeline order: generate → route/filter → store.
export const TOOLS: readonly ToolDef[] = [
  {
    id: "hose",
    name: "syslog-hose",
    label: "hose",
    tagline: "generator",
    icon: "water_drop",
    linkKey: "linkHose",
    sections: [
      { id: "jobs", label: "Jobs", icon: "bolt" },
      { id: "presets", label: "Presets", icon: "category" },
      { id: "tail", label: "Live tail", icon: "terminal" },
    ],
  },
  {
    id: "valve",
    name: "syslog-valve",
    label: "valve",
    tagline: "router & filter",
    icon: "valve",
    linkKey: "linkValve",
    sections: [
      { id: "flow", label: "Flow", icon: "account_tree" },
      { id: "history", label: "History", icon: "history" },
      { id: "tail", label: "Live tail", icon: "terminal" },
    ],
  },
  {
    id: "bucket",
    name: "syslog-bucket",
    label: "bucket",
    tagline: "store & triage",
    icon: "inbox",
    linkKey: "linkBucket",
    sections: [
      { id: "logs", label: "Logs", icon: "description" },
      { id: "attack", label: "ATT&CK", icon: "crisis_alert" },
      { id: "ot", label: "ICS/OT", icon: "factory" },
      { id: "network", label: "Network", icon: "lan" },
      { id: "frameworks", label: "Frameworks", icon: "shield" },
      { id: "buckets", label: "Buckets", icon: "folder" },
      { id: "rules", label: "Rules", icon: "rule" },
    ],
  },
];

export function toolDef(id: ToolId): ToolDef {
  return TOOLS.find((t) => t.id === id)!;
}

// A bare port resolves against the host the browser is already on, so the
// default compose links work from localhost and over the LAN alike.
export function resolveLink(link: string): string {
  if (/^\d+$/.test(link)) return `${location.protocol}//${location.hostname}:${link}/`;
  return link;
}

// hashFor builds an in-app deep link: hashFor("buckets", 3) → "#/buckets/3".
export function hashFor(...parts: (string | number)[]): string {
  return "#/" + parts.map((p) => encodeURIComponent(String(p))).join("/");
}

// toolHref links to a tool (optionally one of its sections). The current
// tool gets a bare hash so navigation stays in-app; another tool gets its
// deployment URL, or null when the deployment doesn't link it (standalone).
export function toolHref(
  current: ToolId,
  links: Record<string, string>,
  tool: ToolId,
  ...section: (string | number)[]
): string | null {
  const hash = section.length ? hashFor(...section) : "#/";
  if (tool === current) return hash;
  const link = links[toolDef(tool).linkKey];
  if (!link) return null;
  const base = resolveLink(link).replace(/#.*$/, "");
  return section.length ? base + hash : base;
}
