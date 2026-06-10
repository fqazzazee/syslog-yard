import type { Bucket, Entry, Filters, Rule, Selection, Stats, Tag } from "./types";

export function filterParams(f: Filters, sel: Selection): URLSearchParams {
  const params = new URLSearchParams();
  if (sel.kind === "bucket") params.set("bucket_id", String(sel.id));
  if (sel.kind === "tag") params.set("tag_id", String(sel.id));
  if (f.q) params.set("q", f.q);
  if (f.host) params.set("host", f.host);
  if (f.app) params.set("app", f.app);
  if (f.severity) params.set("severity", f.severity);
  if (f.status) params.set("status", f.status);
  if (f.range) {
    const from = new Date(Date.now() - Number(f.range) * 60_000);
    params.set("from", from.toISOString());
  }
  return params;
}

async function request<T>(url: string, init?: RequestInit): Promise<T> {
  const res = await fetch(url, init);
  if (!res.ok) {
    const body = await res.text();
    throw new Error(body.trim() || `HTTP ${res.status}`);
  }
  if (res.status === 204) return undefined as T;
  return (await res.json()) as T;
}

function send<T>(method: string, url: string, body: unknown): Promise<T> {
  return request<T>(url, {
    method,
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}

export async function fetchEntries(
  f: Filters,
  sel: Selection,
  opts: { afterId?: number; beforeId?: number; limit?: number } = {},
): Promise<Entry[]> {
  const params = filterParams(f, sel);
  if (opts.afterId !== undefined) params.set("after_id", String(opts.afterId));
  if (opts.beforeId !== undefined) params.set("before_id", String(opts.beforeId));
  params.set("limit", String(opts.limit ?? 200));
  const body = await request<{ entries: Entry[] }>(`/api/entries?${params}`);
  return body.entries;
}

export function liveTailURL(f: Filters, sel: Selection): string {
  const params = filterParams(f, sel);
  const proto = location.protocol === "https:" ? "wss:" : "ws:";
  return `${proto}//${location.host}/api/ws?${params}`;
}

export const fetchStats = () => request<Stats>("/api/stats");

export const fetchHints = () => request<Record<string, string>>("/api/hints");

export const patchEntry = (id: number, patch: { status?: string; priority?: number }) =>
  send<Entry>("PATCH", `/api/entries/${id}`, patch);

export const tagEntry = (id: number, tagId: number) =>
  request<Entry>(`/api/entries/${id}/tags/${tagId}`, { method: "PUT" });

export const untagEntry = (id: number, tagId: number) =>
  request<Entry>(`/api/entries/${id}/tags/${tagId}`, { method: "DELETE" });

export const fetchTags = () => request<{ tags: Tag[] }>("/api/tags").then((b) => b.tags);
export const createTag = (t: Omit<Tag, "id">) => send<Tag>("POST", "/api/tags", t);
export const updateTag = (t: Tag) => send<Tag>("PUT", `/api/tags/${t.id}`, t);
export const deleteTag = (id: number) => request<void>(`/api/tags/${id}`, { method: "DELETE" });

export const fetchBuckets = () =>
  request<{ buckets: Bucket[] }>("/api/buckets").then((b) => b.buckets);
export const createBucket = (b: Omit<Bucket, "id">) => send<Bucket>("POST", "/api/buckets", b);
export const updateBucket = (b: Bucket) => send<Bucket>("PUT", `/api/buckets/${b.id}`, b);
export const deleteBucket = (id: number) =>
  request<void>(`/api/buckets/${id}`, { method: "DELETE" });

export const fetchRules = () => request<{ rules: Rule[] }>("/api/rules").then((b) => b.rules);
export const createRule = (r: Omit<Rule, "id">) => send<Rule>("POST", "/api/rules", r);
export const updateRule = (r: Rule) => send<Rule>("PUT", `/api/rules/${r.id}`, r);
export const deleteRule = (id: number) => request<void>(`/api/rules/${id}`, { method: "DELETE" });
export const applyRule = (id: number) =>
  send<{ affected: number }>("POST", `/api/rules/${id}/apply`, {});
