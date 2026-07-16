// The auth/user-management slice (AuthUser, YardUser, the /api/auth and
// /api/users calls) is shared suite-wide — see apps/shared/web.
import { authApi } from "../../../shared/web/src/yardAuthApi";

export type { AuthUser, YardUser } from "../../../shared/web/src/yardAuthApi";

export type NodeType = "source" | "filter" | "forward" | "cache" | "notify";

export interface NodeConfig {
  transport?: "udp" | "tcp" | "tls" | "udp+tcp"; // udp+tcp: sources only
  port?: number;
  bind?: string;
  host?: string;
  tlsVerify?: boolean; // forward+tls: verify peer against system CAs
  // filter
  severityMax?: number; // pass if syslog severity <= this (0 emerg .. 7 debug)
  program?: string;
  match?: string;
  technique?: string; // MITRE ATT&CK technique id
  // notify: deliver matched messages to a webhook / Slack-Teams hook
  notifyKind?: "webhook" | "slack";
  url?: string;
  ratePerMin?: number;
  // cache
  location?: string; // "" local, else share name
  dir?: string;
  maxSizeMB?: number;
  maxAgeDays?: number;
  rotate?: number;
  compress?: boolean;
}

export const SEVERITIES = [
  "emerg",
  "alert",
  "crit",
  "err",
  "warning",
  "notice",
  "info",
  "debug",
] as const;

export interface GraphNode {
  id: string;
  type: NodeType;
  name: string;
  x: number;
  y: number;
  disabled?: boolean; // toggled off: stays on the canvas, left out on Apply
  config: NodeConfig;
}

export interface GraphEdge {
  from: string;
  fromPort?: string; // filters: "match" | "else"
  to: string;
}

export interface Graph {
  nodes: GraphNode[];
  edges: GraphEdge[];
}

export interface Status {
  running: boolean;
  pid: number;
  restarts: number;
  version: string;
  lastApply: string;
  lastError: string;
  log: string[];
  // Cumulative "processed" message count per graph node id (sources + sinks),
  // from syslog-ng-ctl stats; the UI turns deltas into per-wire throughput.
  throughput?: Record<string, number>;
}

export interface HistoryEntry {
  id: string;
  time: string;
}

export interface CertStatus {
  exists: boolean;
  subject?: string;
  notAfter?: string;
  sans?: string[];
  error?: string;
}

export interface TailEvent {
  seq: number;
  src: string;
  time: string;
  host: string;
  program: string;
  message: string;
}

// MITRE ATT&CK catalog the valve can filter on (served by /api/mitre).
export interface MitreTactic {
  id: string;
  short: string;
  name: string;
}
export interface MitreTechnique {
  id: string;
  name: string;
  tactics: string[];
}
export interface MitreCatalog {
  tactics: MitreTactic[];
  techniques: MitreTechnique[];
}

// NotifyDelivery is one recorded notification attempt.
export interface NotifyDelivery {
  seq: number;
  node: string;
  status: string; // ok | error | dropped
  detail: string;
  time: string;
}

async function check(res: Response): Promise<Response> {
  if (!res.ok) {
    // A 401 outside the auth endpoints means the session died mid-use;
    // tell the app shell to fall back to the login screen.
    if (res.status === 401 && !res.url.includes("/api/auth/")) {
      window.dispatchEvent(new Event("auth-expired"));
    }
    let msg = `${res.status} ${res.statusText}`;
    const raw = (await res.text().catch(() => "")).trim();
    try {
      const body = JSON.parse(raw);
      if (body.error) msg = body.error;
    } catch {
      msg = raw || msg;
    }
    throw new Error(msg);
  }
  return res;
}

export const api = {
  getGraph: (): Promise<Graph> =>
    fetch("/api/graph").then(check).then((r) => r.json()),
  saveGraph: (g: Graph) =>
    fetch("/api/graph", { method: "PUT", body: JSON.stringify(g) }).then(check),
  apply: (): Promise<{ ok: boolean; config: string }> =>
    fetch("/api/apply", { method: "POST" }).then(check).then((r) => r.json()),
  rollback: (id: string) =>
    fetch(`/api/rollback/${id}`, { method: "POST" }).then(check),
  history: (): Promise<HistoryEntry[]> =>
    fetch("/api/history").then(check).then((r) => r.json()),
  status: (): Promise<Status> =>
    fetch("/api/status").then(check).then((r) => r.json()),
  config: (): Promise<string> =>
    fetch("/api/config").then(check).then((r) => r.text()),
  hints: (): Promise<Record<string, string>> =>
    fetch("/api/hints").then(check).then((r) => r.json()),
  mitre: (): Promise<MitreCatalog> =>
    fetch("/api/mitre").then(check).then((r) => r.json()),
  notifyLog: (): Promise<NotifyDelivery[]> =>
    fetch("/api/notify/log").then(check).then((r) => r.json()),
  notifyTest: (kind: string, url: string): Promise<{ ok: boolean }> =>
    fetch("/api/notify/test", { method: "POST", body: JSON.stringify({ kind, url }) })
      .then(check)
      .then((r) => r.json()),
  historyConfig: (id: string): Promise<string> =>
    fetch(`/api/history/${id}/config`).then(check).then((r) => r.text()),
  certs: (): Promise<CertStatus> =>
    fetch("/api/certs").then(check).then((r) => r.json()),
  generateCert: (): Promise<CertStatus> =>
    fetch("/api/certs/selfsigned", { method: "POST" }).then(check).then((r) => r.json()),
  ...authApi,
};
