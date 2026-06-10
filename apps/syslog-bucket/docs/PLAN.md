# syslog-bucket — Build Plan

> An open-source, self-hosted **syslog server + web app modeled on an email client**.
> Receive syslog from anything, then sort, filter, tag, and assign entries the way you
> triage email. Built for cyber, network, **and OT/ICS** security analysts who want
> SIEM-style power with zero learning curve.

**Status:** M1 (ingest spine) and M2 (email UX: buckets, tags, rules engine,
live tail, 3-pane UI) are built. Next: M3 (auth, RBAC, assignment, audit log).
This document is the source of truth for v1.

---

## 1. The metaphor (north star)

Every UI/UX decision maps to an email client analysts already understand:

| Email concept            | syslog-bucket concept                          |
|--------------------------|--------------------------------------------|
| IMAP/SMTP server         | syslog-ng/rsyslog receiver                 |
| Inbox                    | "All Logs" live stream                     |
| Folders                  | **Buckets** (virtual saved-searches)       |
| Mail rules / filters     | **Rules** (condition → actions)            |
| Labels / flags           | **Tags** (color-coded)                     |
| Assigning/owning a thread| **Assignment** to an analyst               |
| Mark read / follow-up    | Status (new / reviewing / resolved)        |
| Archive / auto-delete    | Retention + export                         |

---

## 2. Architecture (Docker Compose)

```
                 ┌────────────────────────────────────────────┐
   Devices  ──►  │ syslog-ng / rsyslog  (UDP/TCP/TLS 514/601)  │
 (FW, Linux,     │  parses RFC3164/5424/CEF → JSON             │
  Claroty CTD)   └───────────────┬────────────────────────────┘
                                 │ structured JSON over a unix socket /
                                 │ network socket / file tail
                 ┌───────────────▼────────────────────────────┐
                 │  syslog-bucket Backend (Go)                     │
                 │  • Ingest worker: read → normalize via      │
                 │    parser plugins → enrich → INSERT         │
                 │  • Rule engine: evaluate rules → tag/assign │
                 │    /notify/priority (at ingest + on demand) │
                 │  • REST (internal) + WebSocket (live tail)  │
                 │  • Auth: local + OIDC, RBAC                 │
                 │  • Retention/export scheduler               │
                 └───────┬───────────────────────┬────────────┘
                         │                        │
                 ┌───────▼────────┐      ┌────────▼─────────┐
                 │  PostgreSQL    │      │ React + TS SPA   │
                 │  (single store)│      │ (3-pane UI)      │
                 └────────────────┘      └──────────────────┘
```

**Ingestion contract:** syslog-ng handles wire protocols + first-pass parsing and emits
**JSON** (via its `json-parser`/template) to a socket the Go ingest worker consumes. This
keeps Go off the raw UDP firehose and gives us a proven, reloadable receiver. Go parser
plugins then do vendor-specific normalization on top.

---

## 3. Locked technology decisions

| Area            | Decision                                                                 |
|-----------------|--------------------------------------------------------------------------|
| Ingestion       | Front with **syslog-ng/rsyslog**, hand structured JSON to the app        |
| Backend         | **Go** (single static binary)                                            |
| Storage         | **PostgreSQL** single store (entries + metadata)                         |
| Frontend        | **React + TypeScript** (Vite), 3-pane email-style layout                 |
| Deploy          | **Docker Compose** (app + Postgres + syslog-ng)                          |
| Auth            | Local accounts **+ OIDC**; roles + per-entry/bucket assignment           |
| Bucket model    | **Virtual / saved-search** (store once, appears in many buckets)         |
| Real-time       | **Live tail over WebSocket**                                             |
| Rule actions    | auto-tag/color, auto-assign, notify, set-priority, suppress              |
| Retention       | Configurable time-based purge **with export-to-Markdown/CSV first**      |
| Search          | Field filters + full-text **and** a query-language power mode            |
| Notifications   | **Slack/Teams + generic webhook**                                        |
| Public API      | **None in v1** (REST is internal to the SPA)                             |

---

## 4. Data model (Postgres, core tables)

- **`sources`** — sending hosts/devices (`ip`, `hostname`, `vendor`, `zone`/`site` for OT).
- **`entries`** — the log records. Key columns: `id`, `received_at`, `device_time`,
  `source_id`, `facility`, `severity`, `app_name`, `host`, `msg` (raw),
  `structured` (JSONB parsed fields), `priority`, `status`, `assignee_id`.
  Indexes: BRIN on `received_at`, GIN on `structured` + `tsvector(msg)` for full-text,
  btree on `(source_id, severity)`.
- **`buckets`** — virtual folders. Stores a **filter definition** (JSON/AST), not rows.
- **`rules`** — `condition` (AST) + ordered `actions[]`.
- **`tags`** — name + color + optional description.
- **`entry_tags`** — many-to-many (entries ↔ tags).
- **`users`, `roles`, `user_roles`** — RBAC + OIDC subject mapping.
- **`notifications`, `notification_channels`** — Slack/Teams/webhook configs.
- **`audit_log`** — who did what (assignments, rule edits, exports).

**Why virtual buckets are cheap:** a bucket is a saved filter compiled to a
parameterized SQL `WHERE`. "Open bucket" = run that query; "live tail" = the WebSocket
pushes new entries matching the same compiled predicate. One entry storage, infinite
views, retroactive rule changes — the Gmail-label model.

---

## 5. Rules engine

- **Shared condition AST** powers buckets, rules, and the search bar (one grammar, three uses).
- Conditions: field comparisons (`host`, `severity>=warning`, `app_name`,
  `structured.action`), free-text, AND/OR/NOT, time windows.
- Actions (ordered, all v1): `auto-tag`, `auto-assign`, `notify`, `set-priority`,
  `suppress/mute`.
- Runs **at ingest** (live) and **on-demand** (apply a new/edited rule to historical
  entries — the retroactive power of virtual buckets).
- Suppressed entries are flagged, not deleted (a rule mistake is recoverable).

---

## 6. Search (two modes, one engine)

- **Guided:** faceted dropdowns (host, severity, facility, app, time range) + free-text box.
- **Power mode:** small query language compiling to the same AST, e.g.
  `host=fw1 severity>=warning "failed login" last:24h`. Postgres FTS + JSONB handles
  this without a second datastore.

---

## 7. Auth & collaboration

- **Local accounts + OIDC** (Keycloak / Azure AD / Authentik / Google) via
  `oauth2`/`go-oidc`.
- Roles: **Admin / Analyst / Read-only**. Assignment = per-entry or per-bucket ownership
  (ticket-style queues: "My assigned", "Unassigned").
- Architected multi-tenant-*ready* (nullable `org_id` everywhere) but v1 ships
  single-workspace to stay simple.

---

## 8. Parsers (plugin layer)

Go interface `Parser{ Match(entry) bool; Normalize(entry) map }`, registered in a
pipeline. v1 packs:

- Generic RFC3164/5424 + **CEF/LEEF + key=value** auto-detect.
- Network: Cisco IOS/ASA, Fortinet, Palo Alto, MikroTik, Juniper.
- Linux/Unix hosts (sshd, sudo, auth, kernel, journald-forward).
- Firewalls/IDS: pfSense/OPNsense, Suricata/Snort.
- **Claroty CTD** (CEF-based OT pack — extracts asset, zone, alert type).

---

## 9. Real-time, retention, export, notifications

- **Live tail:** WebSocket channel per open bucket; server pushes matching new entries.
- **Retention:** configurable window (e.g. 90d) → scheduler **exports the bucket to
  Markdown + CSV** → then purges. Nothing lost.
- **Manual export:** any bucket → `.md` (readable report) or `.csv` (analysis) on demand.
- **Notifications:** Slack/Teams + generic webhook, fired by the `notify` rule action,
  with rate-limiting to avoid alert storms.
- **No public API in v1:** REST stays internal to the SPA; tokens/public API deferred.

---

## 10. Repo layout

```
syslog-bucket/
├── cmd/syslog-bucket/main.go         # single binary entrypoint
├── internal/
│   ├── ingest/                   # socket reader, worker pool
│   ├── parsers/                  # plugin packs (cisco, claroty, ...)
│   ├── rules/                    # AST, evaluator, actions
│   ├── store/                    # Postgres (sqlc or pgx), migrations
│   ├── api/                      # REST handlers
│   ├── ws/                       # live-tail hub
│   ├── auth/                     # local + OIDC, RBAC
│   ├── retention/                # purge+export scheduler
│   └── notify/                   # slack/teams/webhook
├── web/                          # React + TS SPA (Vite, 3-pane)
├── deploy/
│   ├── docker-compose.yml        # app + postgres + syslog-ng
│   └── syslog-ng/syslog-ng.conf  # JSON-emitting config
├── migrations/
└── docs/PLAN.md                  # this file
```

---

## 11. Phasing

- **M1 — Ingest spine:** syslog-ng→Go→Postgres, generic parser, raw "All Logs" view +
  basic field search. *Proves the pipe works.*
- **M2 — Email UX:** buckets (virtual), tags+colors, rules engine
  (tag/assign/priority/suppress), 3-pane React UI, live tail.
- **M3 — Team:** local+OIDC auth, RBAC, assignment queues, audit log.
- **M4 — Ops:** retention+export, Slack/Teams/webhook notifications, vendor parser packs
  (incl. Claroty), query-language mode.

The "all features in v1" goal lands across M1–M4; this ordering sequences them so the
tool is *usable* after M2 and *shippable* after M4.

---

## 12. Open risks / decisions to revisit

1. **Live tail + virtual buckets at scale:** evaluating every rule/bucket predicate
   against every incoming entry is fine at small volume; for larger teams we may need a
   compiled predicate index or a lightweight stream matcher. Designed-for, not built in M1.
2. **syslog-ng config exposure:** hide it behind an opinionated default, or let admins
   edit it in-app? Affects the "simple setup" promise.
3. **Postgres full-text vs. volume:** great up to mid-size; sustained thousands/sec may
   need partitioning or an optional ClickHouse entries backend (the `store` interface
   leaves that door open).
