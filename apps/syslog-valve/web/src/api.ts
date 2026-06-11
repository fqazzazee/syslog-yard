export type NodeType = "source" | "filter" | "forward" | "cache";

export interface NodeConfig {
  transport?: "udp" | "tcp" | "tls";
  port?: number;
  bind?: string;
  host?: string;
  tlsVerify?: boolean; // forward+tls: verify peer against system CAs
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

// AuthUser comes from syslog-bucket, the yard's identity provider; auth is
// active only when the deployment sets YARD_AUTH_URL.
export interface AuthUser {
  id: number;
  username: string;
  display_name: string;
  role: string;
  has_password?: boolean;
}

// YardUser is the fuller record the bucket's user-management API returns.
export interface YardUser extends AuthUser {
  email: string;
  disabled: boolean;
  has_password: boolean;
  oidc: boolean;
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
  historyConfig: (id: string): Promise<string> =>
    fetch(`/api/history/${id}/config`).then(check).then((r) => r.text()),
  certs: (): Promise<CertStatus> =>
    fetch("/api/certs").then(check).then((r) => r.json()),
  generateCert: (): Promise<CertStatus> =>
    fetch("/api/certs/selfsigned", { method: "POST" }).then(check).then((r) => r.json()),
  authInfo: (): Promise<{ enabled: boolean }> =>
    fetch("/api/auth/info").then(check).then((r) => r.json()),
  me: (): Promise<AuthUser> =>
    fetch("/api/auth/me").then(check).then((r) => r.json()),
  login: (username: string, password: string): Promise<AuthUser> =>
    fetch("/api/auth/login", { method: "POST", body: JSON.stringify({ username, password }) })
      .then(check)
      .then((r) => r.json()),
  logout: (): Promise<Response> =>
    fetch("/api/auth/logout", { method: "POST" }).then(check),
  changePassword: (oldPw: string, newPw: string): Promise<Response> =>
    fetch("/api/auth/password", { method: "PUT", body: JSON.stringify({ old: oldPw, new: newPw }) }).then(check),
  users: (): Promise<YardUser[]> =>
    fetch("/api/users").then(check).then((r) => r.json()).then((b: { users: YardUser[] }) => b.users),
  createUser: (u: { username: string; display_name: string; email: string; role: string; password: string }): Promise<YardUser> =>
    fetch("/api/users", { method: "POST", body: JSON.stringify(u) }).then(check).then((r) => r.json()),
  updateUser: (
    id: number,
    u: { display_name: string; email: string; role: string; disabled: boolean; password?: string },
  ): Promise<YardUser> =>
    fetch(`/api/users/${id}`, { method: "PUT", body: JSON.stringify(u) }).then(check).then((r) => r.json()),
  deleteUser: (id: number): Promise<Response> =>
    fetch(`/api/users/${id}`, { method: "DELETE" }).then(check),
};
