import { ApiError, jsonInit, request as sharedRequest } from "../../../shared/web/src/http";
import type {
  AuditEvent,
  AuditFilters,
  AuthInfo,
  Bucket,
  BucketShare,
  Channel,
  Coverage,
  Delivery,
  Entry,
  Filters,
  Framework,
  MitreCatalog,
  NetConfig,
  NetFeedStatus,
  NetSummary,
  OTCatalog,
  Rule,
  Selection,
  Settings,
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
  if (sel.kind === "frameworkitem") {
    params.set("framework", sel.fw);
    params.set("item", sel.id);
  }
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

// Errors, the 401 → sign-in signal and JSON bodies are handled by the
// suite-wide helpers in apps/shared/web (one parser for all three tools).
export { ApiError };

function request<T>(url: string, init?: RequestInit): Promise<T> {
  return sharedRequest<T>(url, init);
}

function send<T>(method: string, url: string, body: unknown): Promise<T> {
  return sharedRequest<T>(url, jsonInit(method, body));
}

// call is a body-less state change (PUT/POST), still sent as JSON: the
// server only accepts application/json on state-changing requests.
function call<T>(method: string, url: string): Promise<T> {
  return send<T>(method, url, {});
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

export const fetchFrameworks = () =>
  request<{ frameworks: Framework[] }>("/api/frameworks").then((b) => b.frameworks);
export const createFramework = (f: Omit<Framework, "id">) =>
  send<Framework>("POST", "/api/frameworks", f);
export const updateFramework = (f: Framework) =>
  send<Framework>("PUT", `/api/frameworks/${encodeURIComponent(f.id)}`, f);
export const deleteFramework = (id: string) =>
  request<void>(`/api/frameworks/${encodeURIComponent(id)}`, { method: "DELETE" });

// Per-alert-type counts under the current filters (drives the OT view).
export const fetchOtSummary = (f: Filters, sel: Selection) =>
  request<{ counts: Record<string, number> }>(`/api/ot/summary?${filterParams(f, sel)}`).then((b) => b.counts);

// Per-device-class counts (drives the data-sensitivity framework view).
export const fetchClassSummary = (f: Filters, sel: Selection) =>
  request<{ counts: Record<string, number> }>(`/api/class/summary?${filterParams(f, sel)}`).then((b) => b.counts);

// --- network security view ---

export const fetchNetSummary = (minutes: number) =>
  request<NetSummary>(`/api/net/summary?minutes=${minutes}`);

export const fetchNetEntries = (q: { class?: string; ip?: string; minutes: number }) => {
  const params = new URLSearchParams();
  if (q.class) params.set("class", q.class);
  if (q.ip) params.set("ip", q.ip);
  params.set("minutes", String(q.minutes));
  return request<{ entries: Entry[] }>(`/api/net/entries?${params}`).then((b) => b.entries);
};

export const fetchNetConfig = () =>
  request<{ config: NetConfig; feeds: NetFeedStatus[] }>("/api/net/config");

// pending: the feed fetch outlived the request (202) and continues in the
// background; poll fetchNetConfig for the result.
export interface NetRefreshResult {
  ok: boolean;
  pending?: boolean;
  feeds: NetFeedStatus[];
}

export const putNetConfig = (c: NetConfig) => send<NetRefreshResult>("PUT", "/api/net/config", c);

export const refreshNetFeeds = () => call<NetRefreshResult>("POST", "/api/net/refresh");

// Classification coverage for the current window. For a whole-framework
// selection we add the framework param so the server also returns `covered`.
export const fetchCoverage = (f: Filters, sel: Selection) => {
  const params = filterParams(f, sel);
  if (sel.kind === "framework") params.set("framework", sel.fw);
  return request<Coverage>(`/api/coverage?${params}`);
};

export const patchEntry = (id: number, patch: { status?: string; priority?: number }) =>
  send<Entry>("PATCH", `/api/entries/${id}`, patch);

export const tagEntry = (id: number, tagId: number) => call<Entry>("PUT", `/api/entries/${id}/tags/${tagId}`);

export const untagEntry = (id: number, tagId: number) =>
  request<Entry>(`/api/entries/${id}/tags/${tagId}`, { method: "DELETE" });

// Hand-classification: add/remove a MITRE technique or OT code on one entry.
export const addEntryMitre = (id: number, code: string) =>
  call<Entry>("PUT", `/api/entries/${id}/mitre/${encodeURIComponent(code)}`);
export const delEntryMitre = (id: number, code: string) =>
  request<Entry>(`/api/entries/${id}/mitre/${encodeURIComponent(code)}`, { method: "DELETE" });
export const addEntryOT = (id: number, code: string) =>
  call<Entry>("PUT", `/api/entries/${id}/ot/${encodeURIComponent(code)}`);
export const delEntryOT = (id: number, code: string) =>
  request<Entry>(`/api/entries/${id}/ot/${encodeURIComponent(code)}`, { method: "DELETE" });

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
export const logout = () => call<void>("POST", "/api/auth/logout");

// --- admin settings (OIDC + session) ---

export const fetchSettings = () => request<Settings>("/api/settings");
// client_secret is only included when the admin actually entered a new one.
export const saveOIDCSettings = (o: {
  enabled: boolean;
  issuer: string;
  client_id: string;
  redirect_url: string;
  name: string;
  default_role: string;
  client_secret?: string;
}) => send<{ ok: boolean; warning?: string }>("PUT", "/api/settings/oidc", o);
export const saveSessionSettings = (idle_minutes: number) =>
  send<{ ok: boolean }>("PUT", "/api/settings/session", { idle_minutes });

export const fetchUsers = () => request<{ users: User[] }>("/api/users").then((b) => b.users);
// Creating, editing and deleting users lives in the shared account menu
// (apps/shared/web/src/AccountMenu.tsx); the bucket only lists them.

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
export const testChannel = (id: number) => call<{ ok: boolean }>("POST", `/api/channels/${id}/test`);
export const fetchNotificationLog = (channelId?: number) =>
  request<{ deliveries: Delivery[] }>(
    `/api/notifications/log${channelId ? `?channel_id=${channelId}` : ""}`,
  ).then((b) => b.deliveries);

export const fetchRules = () => request<{ rules: Rule[] }>("/api/rules").then((b) => b.rules);
export const createRule = (r: Omit<Rule, "id">) => send<Rule>("POST", "/api/rules", r);
export const updateRule = (r: Rule) => send<Rule>("PUT", `/api/rules/${r.id}`, r);
export const deleteRule = (id: number) => request<void>(`/api/rules/${id}`, { method: "DELETE" });
// affected counts distinct entries the run actually changed (so a re-run
// reports 0), matched the entries the condition selected; skipped lists
// action types the server does not replay over history (e.g. ["notify"]).
// Older servers omit matched and skipped.
export const applyRule = (id: number) =>
  call<{ affected: number; matched?: number; skipped?: string[] }>("POST", `/api/rules/${id}/apply`);

// --- audit log (admin only) ---

// One page of the audit log, newest first. Pass the previous page's
// next_cursor as cursor; a null next_cursor means there is no older page.
export const fetchAudit = (f: AuditFilters, opts: { cursor?: string; limit?: number } = {}) => {
  const params = new URLSearchParams();
  if (f.actor.trim()) params.set("actor", f.actor.trim());
  if (f.action) params.set("action", f.action);
  if (f.targetType) params.set("target_type", f.targetType);
  if (f.result) params.set("success", f.result === "success" ? "true" : "false");
  // datetime-local values are local wall-clock times; the API wants RFC3339.
  if (f.since) params.set("since", new Date(f.since).toISOString());
  if (f.until) params.set("until", new Date(f.until).toISOString());
  if (opts.cursor) params.set("cursor", opts.cursor);
  params.set("limit", String(opts.limit ?? 50));
  return request<{ events: AuditEvent[]; next_cursor: string | null }>(`/api/audit?${params}`);
};
