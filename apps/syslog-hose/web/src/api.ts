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
    let msg = `${res.status}`;
    try {
      const body = await res.json();
      if (body.error) msg = body.error;
    } catch {
      /* not json */
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
  preview: (body: {
    preset?: string;
    yaml?: string;
    count?: number;
    hostname?: string;
    format?: string;
  }) => req<{ samples: string[] }>("/api/preview", json("POST", body)),
};
