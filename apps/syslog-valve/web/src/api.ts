export type NodeType = "source" | "filter" | "forward" | "cache";

export interface NodeConfig {
  transport?: "udp" | "tcp";
  port?: number;
  bind?: string;
  host?: string;
  // filter
  severityMax?: number; // pass if syslog severity <= this (0 emerg .. 7 debug)
  program?: string;
  match?: string;
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
}

export interface HistoryEntry {
  id: string;
  time: string;
}

async function check(res: Response): Promise<Response> {
  if (!res.ok) {
    let msg = `${res.status} ${res.statusText}`;
    try {
      const body = await res.json();
      if (body.error) msg = body.error;
    } catch {
      /* not JSON */
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
};
