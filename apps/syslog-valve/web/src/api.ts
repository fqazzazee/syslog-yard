// The auth/user-management slice (AuthUser, YardUser, the /api/auth and
// /api/users calls) is shared suite-wide — see apps/shared/web.
import { ensureOk, jsonInit, request } from "../../../shared/web/src/http";
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

// NotifyStats are cumulative per-node delivery counters (keyed by node id).
export interface NotifyStats {
  node: string;
  ratePerMin: number;
  sent: number;
  failed: number;
  dropped: number; // rate limited or queue full
}

// Apply / rollback answer ok, plus a warning when the config was installed
// but syslog-ng wasn't running to confirm it.
export interface ActivateResult {
  ok: boolean;
  config?: string;
  warning?: string;
}

const check = (res: Response) => ensureOk(res);
const jsonBody = (method: string, body: unknown) => jsonInit(method, body);

export const api = {
  getGraph: (): Promise<Graph> =>
    fetch("/api/graph").then(check).then((r) => r.json()),
  saveGraph: (g: Graph) => fetch("/api/graph", jsonBody("PUT", g)).then(check),
  apply: () => request<ActivateResult>("/api/apply", jsonBody("POST", {})),
  rollback: (id: string) => request<ActivateResult>(`/api/rollback/${encodeURIComponent(id)}`, jsonBody("POST", {})),
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
  notifyTest: (kind: string, url: string) => request<{ ok: boolean }>("/api/notify/test", jsonBody("POST", { kind, url })),
  notifyStats: () => request<Record<string, NotifyStats>>("/api/notify/stats"),
  historyConfig: (id: string): Promise<string> =>
    fetch(`/api/history/${encodeURIComponent(id)}/config`).then(check).then((r) => r.text()),
  certs: (): Promise<CertStatus> =>
    fetch("/api/certs").then(check).then((r) => r.json()),
  generateCert: () => request<CertStatus>("/api/certs/selfsigned", jsonBody("POST", {})),
  ...authApi,
};
