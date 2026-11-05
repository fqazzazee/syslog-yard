// The auth/user-management slice (AuthUser, YardUser, the /api/auth and
// /api/users calls) is shared suite-wide — see apps/shared/web.
import { jsonInit, request } from "../../../shared/web/src/http";
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

const req = request;
const json = jsonInit;

export const api = {
  jobs: () => req<Job[]>("/api/jobs"),
  createJob: (cfg: Partial<Job>) => req<Job>("/api/jobs", json("POST", cfg)),
  updateJob: (id: string, cfg: Partial<Job>) =>
    req<Job>(`/api/jobs/${encodeURIComponent(id)}`, json("PUT", cfg)),
  deleteJob: (id: string) => req<void>(`/api/jobs/${encodeURIComponent(id)}`, { method: "DELETE" }),
  startJob: (id: string) => req<void>(`/api/jobs/${encodeURIComponent(id)}/start`, { method: "POST" }),
  stopJob: (id: string) => req<void>(`/api/jobs/${encodeURIComponent(id)}/stop`, { method: "POST" }),
  stopAll: () => req<void>("/api/jobs/stop-all", { method: "POST" }),
  presets: () => req<PresetSummary[]>("/api/presets"),
  preset: (name: string) =>
    req<{ name: string; builtin: boolean; yaml: string }>(
      `/api/presets/${encodeURIComponent(name)}`,
    ),
  // Preset bodies are YAML, so this one stays text/plain.
  savePreset: (yaml: string) =>
    req<{ name: string }>("/api/presets", {
      method: "POST",
      headers: { "Content-Type": "text/plain; charset=utf-8" },
      body: yaml,
    }),
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
