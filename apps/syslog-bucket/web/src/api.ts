import type {
  AuthInfo,
  Bucket,
  BucketShare,
  Channel,
  Delivery,
  Entry,
  Filters,
  MitreCatalog,
  OTCatalog,
  Rule,
  Selection,
  Stats,
  Tag,
  User,
} from "./types";

export function filterParams(f: Filters, sel: Selection): URLSearchParams {
  const params = new URLSearchParams();
  if (sel.kind === "bucket") params.set("bucket_id", String(sel.id));
  if (sel.kind === "tag") params.set("tag_id", String(sel.id));
  if (sel.kind === "technique") params.set("mitre", sel.id);
  if (sel.kind === "otalert") params.set("ot", sel.id);
  if (f.q) params.set("q", f.q);
  if (f.host) params.set("host", f.host);
  if (f.app) params.set("app", f.app);
  if (f.severity) params.set("severity", f.severity);
  if (f.status) params.set("status", f.status);
  if (f.deviceClass) params.set("device_class", f.deviceClass);
  if (f.range) {
    const from = new Date(Date.now() - Number(f.range) * 60_000);
    params.set("from", from.toISOString());
  }
  if (f.sort && f.sort !== "time") {
    params.set("sort", f.sort);
    params.set("dir", f.desc ? "desc" : "asc");
  }
  return params;
}

async function request<T>(url: string, init?: RequestInit): Promise<T> {
  const res = await fetch(url, init);
  if (!res.ok) {
    // A 401 outside the auth endpoints means the session died mid-use;
    // tell the app shell to fall back to the login screen.
    if (res.status === 401 && !url.startsWith("/api/auth/")) {
      window.dispatchEvent(new Event("auth-expired"));
    }
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

export const fetchMitre = () => request<MitreCatalog>("/api/mitre");

// Per-technique counts under the current filters (drives the MITRE view).
export const fetchMitreSummary = (f: Filters, sel: Selection) =>
  request<{ counts: Record<string, number> }>(`/api/mitre/summary?${filterParams(f, sel)}`).then(
    (b) => b.counts,
  );

export const fetchOt = () => request<OTCatalog>("/api/ot");

// Per-alert-type counts under the current filters (drives the OT view).
export const fetchOtSummary = (f: Filters, sel: Selection) =>
  request<{ counts: Record<string, number> }>(`/api/ot/summary?${filterParams(f, sel)}`).then((b) => b.counts);

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

// --- auth & users ---

export const fetchAuthInfo = () => request<AuthInfo>("/api/auth/info");
export const fetchMe = () => request<User>("/api/auth/me");
export const login = (username: string, password: string) =>
  send<User>("POST", "/api/auth/login", { username, password });
export const logout = () => request<void>("/api/auth/logout", { method: "POST" });
export const changePassword = (oldPw: string, newPw: string) =>
  send<void>("PUT", "/api/auth/password", { old: oldPw, new: newPw });

export const fetchUsers = () => request<{ users: User[] }>("/api/users").then((b) => b.users);
export const createUser = (u: { username: string; display_name: string; email: string; role: string; password: string }) =>
  send<User>("POST", "/api/users", u);
export const updateUser = (
  id: number,
  u: { display_name: string; email: string; role: string; disabled: boolean; password?: string },
) => send<User>("PUT", `/api/users/${id}`, u);
export const deleteUser = (id: number) => request<void>(`/api/users/${id}`, { method: "DELETE" });

export const fetchBucketShares = (bucketId: number) =>
  request<{ shares: BucketShare[] }>(`/api/buckets/${bucketId}/shares`).then((b) => b.shares);
export const putBucketShares = (bucketId: number, shares: BucketShare[]) =>
  send<{ shares: BucketShare[] }>("PUT", `/api/buckets/${bucketId}/shares`, { shares });

// --- notification channels ---

export const fetchChannels = () =>
  request<{ channels: Channel[] }>("/api/channels").then((b) => b.channels);
export const createChannel = (c: Omit<Channel, "id">) => send<Channel>("POST", "/api/channels", c);
export const updateChannel = (c: Channel) => send<Channel>("PUT", `/api/channels/${c.id}`, c);
export const deleteChannel = (id: number) =>
  request<void>(`/api/channels/${id}`, { method: "DELETE" });
export const testChannel = (id: number) =>
  send<{ ok: boolean }>("POST", `/api/channels/${id}/test`, {});
export const fetchNotificationLog = (channelId?: number) =>
  request<{ deliveries: Delivery[] }>(
    `/api/notifications/log${channelId ? `?channel_id=${channelId}` : ""}`,
  ).then((b) => b.deliveries);

export const fetchRules = () => request<{ rules: Rule[] }>("/api/rules").then((b) => b.rules);
export const createRule = (r: Omit<Rule, "id">) => send<Rule>("POST", "/api/rules", r);
export const updateRule = (r: Rule) => send<Rule>("PUT", `/api/rules/${r.id}`, r);
export const deleteRule = (id: number) => request<void>(`/api/rules/${id}`, { method: "DELETE" });
export const applyRule = (id: number) =>
  send<{ affected: number }>("POST", `/api/rules/${id}/apply`, {});
