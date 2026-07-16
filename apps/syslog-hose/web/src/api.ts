// The auth/user-management slice (AuthUser, YardUser, the /api/auth and
// /api/users calls) is shared suite-wide — see apps/shared/web.
import { authApi } from "../../../shared/web/src/yardAuthApi";

export type { AuthUser, YardUser } from "../../../shared/web/src/yardAuthApi";

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
  ...authApi,
  preview: (body: {
    preset?: string;
    yaml?: string;
    count?: number;
    hostname?: string;
    format?: string;
  }) => req<{ samples: string[] }>("/api/preview", json("POST", body)),
};
