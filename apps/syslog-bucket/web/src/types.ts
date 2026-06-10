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
  tag_ids: number[];
}

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
}

export interface Action {
  type: "tag" | "set_priority" | "suppress";
  tag_id?: number;
  priority?: number;
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
  range: string; // "" = all time, otherwise minutes
}

// What the middle pane is showing: the inbox, a bucket, or one tag.
export type Selection =
  | { kind: "all" }
  | { kind: "bucket"; id: number }
  | { kind: "tag"; id: number };

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

export const STATUS_NAMES = ["new", "reviewing", "resolved"] as const;
