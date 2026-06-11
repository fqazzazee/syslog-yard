export interface Job {
  id: string;
  name: string;
  preset: string;
  host: string;
  port: number;
  transport: "udp" | "tcp" | "tls";
  tlsInsecure: boolean;
  format: string;
  rate: number;
  rateMode: string;
  jitterPct: number;
  burstFactor: number;
  burstEvery: number;
  burstLen: number;
  durationSec: number;
  maxEvents: number;
  hostname: string;
  appname: string;
  facility: number;
  autostart: boolean;
  running: boolean;
  sent: number;
  errors: number;
  lastError?: string;
  startedAt?: string;
  actualEps: number;
}

export interface PresetSummary {
  name: string;
  vendor: string;
  description: string;
  format: string;
  builtin: boolean;
  eventCount: number;
}

export interface TailEvent {
  seq: number;
  jobId: string;
  jobName: string;
  time: string;
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

async function req<T>(url: string, init?: RequestInit): Promise<T> {
  const res = await fetch(url, init);
  if (!res.ok) {
    // A 401 outside the auth endpoints means the session died mid-use;
    // tell the app shell to fall back to the login screen.
    if (res.status === 401 && !url.startsWith("/api/auth/")) {
      window.dispatchEvent(new Event("auth-expired"));
    }
    let msg = `${res.status}`;
    const raw = (await res.text().catch(() => "")).trim();
    try {
      const body = JSON.parse(raw);
      msg = body.error || msg;
    } catch {
      msg = raw || msg;
    }
    throw new Error(msg);
  }
  if (res.status === 204) return undefined as T;
  return res.json();
}

const json = (method: string, body: unknown): RequestInit => ({
  method,
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify(body),
});

export const api = {
  jobs: () => req<Job[]>("/api/jobs"),
  createJob: (cfg: Partial<Job>) => req<Job>("/api/jobs", json("POST", cfg)),
  updateJob: (id: string, cfg: Partial<Job>) =>
    req<Job>(`/api/jobs/${id}`, json("PUT", cfg)),
  deleteJob: (id: string) => req<void>(`/api/jobs/${id}`, { method: "DELETE" }),
  startJob: (id: string) => req<void>(`/api/jobs/${id}/start`, { method: "POST" }),
  stopJob: (id: string) => req<void>(`/api/jobs/${id}/stop`, { method: "POST" }),
  stopAll: () => req<void>("/api/jobs/stop-all", { method: "POST" }),
  presets: () => req<PresetSummary[]>("/api/presets"),
  preset: (name: string) =>
    req<{ name: string; builtin: boolean; yaml: string }>(
      `/api/presets/${encodeURIComponent(name)}`,
    ),
  savePreset: (yaml: string) =>
    req<{ name: string }>("/api/presets", { method: "POST", body: yaml }),
  deletePreset: (name: string) =>
    req<void>(`/api/presets/${encodeURIComponent(name)}`, { method: "DELETE" }),
  hints: () => req<Record<string, string>>("/api/hints"),
  authInfo: () => req<{ enabled: boolean }>("/api/auth/info"),
  me: () => req<AuthUser>("/api/auth/me"),
  login: (username: string, password: string) =>
    req<AuthUser>("/api/auth/login", json("POST", { username, password })),
  logout: () => req<void>("/api/auth/logout", { method: "POST" }),
  changePassword: (oldPw: string, newPw: string) =>
    req<void>("/api/auth/password", json("PUT", { old: oldPw, new: newPw })),
  users: () => req<{ users: YardUser[] }>("/api/users").then((b) => b.users),
  createUser: (u: { username: string; display_name: string; email: string; role: string; password: string }) =>
    req<YardUser>("/api/users", json("POST", u)),
  updateUser: (
    id: number,
    u: { display_name: string; email: string; role: string; disabled: boolean; password?: string },
  ) => req<YardUser>(`/api/users/${id}`, json("PUT", u)),
  deleteUser: (id: number) => req<void>(`/api/users/${id}`, { method: "DELETE" }),
  preview: (body: {
    preset?: string;
    yaml?: string;
    count?: number;
    hostname?: string;
    format?: string;
  }) => req<{ samples: string[] }>("/api/preview", json("POST", body)),
};
