export interface Entry {
  id: number;
  received_at: string;
  device_time?: string;
  source_id?: number;
  source_ip?: string;
  facility?: number;
  severity: number;
  app_name: string;
  host: string;
  msg: string;
  structured: Record<string, unknown>;
  priority: number;
  status: string;
  suppressed: boolean;
  device_class: string;
  mitre: string[]; // ATT&CK technique IDs mapped at ingest
  ot: string[]; // Claroty OT alert-type codes mapped at ingest
  tag_ids: number[];
}

// MITRE ATT&CK catalog served by /api/mitre (the subset this build maps).
export interface MitreTactic {
  id: string;
  short: string;
  name: string;
}
export interface MitreTechnique {
  id: string;
  name: string;
  tactics: string[]; // tactic short names
  url: string;
}
export interface MitreCatalog {
  tactics: MitreTactic[];
  techniques: MitreTechnique[];
}

// Claroty-style OT alert catalog served by /api/ot. Categories (Security,
// Integrity) are the columns; alert types are the cells.
export interface OTCategory {
  id: string;
  short: string;
  name: string;
}
export interface OTAlertType {
  id: string; // short code, e.g. "CL-KT"
  name: string;
  categories: string[]; // category short names
}
export interface OTCatalog {
  categories: OTCategory[];
  alert_types: OTAlertType[];
}

// Compliance frameworks served by /api/frameworks. A framework is a crosswalk:
// groups are the matrix columns, items the cells, each mapping to the mitre
// techniques / ot codes that satisfy it.
export interface FrameworkGroup {
  id: string;
  name: string;
}
export interface FrameworkItem {
  id: string;
  name: string;
  group: string;
  mitre?: string[];
  ot?: string[];
  class?: string[]; // device classes that satisfy it (data-sensitivity)
}
export interface Framework {
  id: string;
  name: string;
  short: string;
  desc: string;
  groups: FrameworkGroup[];
  items: FrameworkItem[];
}

// Sort key for the log table. "time" is the default (newest first).
export type SortKey = "time" | "severity" | "priority" | "host" | "app" | "device_class";

export interface Stats {
  approx_total: number;
  last_minute: number;
}

// Cond mirrors the backend condition AST (internal/rules). A node sets at
// most one group.
export interface Cond {
  all?: Cond[];
  any?: Cond[];
  not?: Cond;
  field?: string;
  op?: string;
  value?: string | number;
  text?: string;
  tag_id?: number;
  mitre?: string; // entry mapped to this ATT&CK technique
  ot?: string; // entry mapped to this Claroty OT alert code
  last_seconds?: number;
}

export interface Tag {
  id: number;
  name: string;
  color: string;
  description: string;
}

export interface Bucket {
  id: number;
  name: string;
  description: string;
  condition: Cond;
  position: number;
  owner_id?: number;
  owner_name?: string;
  can_edit: boolean;
  shared: boolean;
}

export type Role = "admin" | "analyst" | "viewer";

export interface User {
  id: number;
  username: string;
  display_name: string;
  email: string;
  role: Role;
  disabled: boolean;
  has_password: boolean;
  oidc: boolean;
}

// AuthInfo is public (pre-login): which sign-in methods the server offers.
export interface AuthInfo {
  oidc: { enabled: boolean; name?: string };
}

// Admin-editable runtime settings (OIDC + session), served by /api/settings.
export interface OIDCSettings {
  enabled: boolean;
  issuer: string;
  client_id: string;
  redirect_url: string;
  name: string;
  default_role: Role;
  has_secret: boolean; // the secret itself is never sent to the client
  source: "db" | "env" | "none"; // where the effective config comes from
}
export interface SessionSettings {
  idle_minutes: number;
}
export interface Settings {
  oidc: OIDCSettings;
  session: SessionSettings;
}

export interface BucketShare {
  user_id: number;
  username: string;
  display_name?: string;
  can_edit: boolean;
}

export interface Action {
  type: "tag" | "set_priority" | "suppress" | "notify" | "set_mitre" | "set_ot";
  tag_id?: number;
  priority?: number;
  channel_id?: number;
  mitre?: string[]; // set_mitre: ATT&CK technique IDs to stamp
  ot?: string[]; // set_ot: Claroty OT alert codes to stamp
}

// Coverage gap from /api/coverage: how much of the window is classified.
export interface Coverage {
  total: number;
  mitre: number;
  ot: number;
  covered?: number; // present when a ?framework= was requested
}

// Notification channel. config is kind-specific; the SMTP password is
// write-only (blanked on read, with has_password flagging whether one is set).
export type ChannelKind = "webhook" | "slack" | "smtp";

export interface Channel {
  id: number;
  name: string;
  kind: ChannelKind;
  config: Record<string, unknown>;
  enabled: boolean;
  rate_per_min: number;
}

export interface Delivery {
  id: number;
  channel_id: number;
  entry_id?: number;
  rule_id?: number;
  status: string; // ok | error | dropped
  detail: string;
  sent_at: string;
}

export interface Rule {
  id: number;
  name: string;
  enabled: boolean;
  position: number;
  condition: Cond;
  actions: Action[];
}

export interface Filters {
  q: string;
  host: string;
  app: string;
  severity: string; // "" = any, otherwise "0".."7" meaning "this level or worse"
  status: string; // "" = any
  deviceClass: string; // "" = any, else a device class
  range: string; // "" = all time, otherwise minutes
  sort: SortKey;
  desc: boolean;
}

// What the middle pane is showing: the inbox, a bucket, one tag, the ATT&CK
// matrix, or the entries for one technique.
export type Selection =
  | { kind: "all" }
  | { kind: "bucket"; id: number }
  | { kind: "tag"; id: number }
  | { kind: "mitre" }
  | { kind: "technique"; id: string }
  | { kind: "ot" }
  | { kind: "otalert"; id: string }
  | { kind: "framework"; fw: string }
  | { kind: "frameworkitem"; fw: string; id: string }
  | { kind: "net" };

// --- network security view (read-time IP classification) ---

export interface NetFeedStatus {
  id: string;
  label: string;
  category: string; // malicious | tor | o365 | custom
  enabled: boolean;
  prefixes: number;
  fetched_at: string;
  error?: string;
}

export interface NetCategoryCount {
  id: string; // set id, drill down with class=set:<id>
  label: string;
  category: string;
  count: number;
}

export interface NetIPHit {
  ip: string;
  feeds: string[];
  count: number;
  last_seen: string;
  entry_ids: number[];
}

export interface NetSummary {
  window_minutes: number;
  scanned: number;
  truncated: boolean;
  directions: Record<string, number>;
  scopes: Record<string, number>;
  categories: NetCategoryCount[];
  malicious: NetIPHit[];
  feeds: NetFeedStatus[];
}

export interface NetCustomCat {
  name: string;
  cidrs: string[];
}

export interface NetConfig {
  feeds: Record<string, boolean>;
  custom: NetCustomCat[];
}

export const SEVERITY_NAMES = [
  "emerg",
  "alert",
  "crit",
  "err",
  "warning",
  "notice",
  "info",
  "debug",
] as const;

export const PRIORITY_NAMES = ["—", "Low", "Med", "High"] as const;

// Coarse device classes from internal/classify (server-side).
export const DEVICE_CLASSES = ["firewall", "network", "host", "windows", "ot"] as const;

export const STATUS_NAMES = ["new", "reviewing", "resolved", "benign"] as const;
