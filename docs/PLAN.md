# syslog-yard — Build Plan

One yard, three tools. **syslog-yard** is an open-source, self-hosted syslog toolkit
deployed as plain containers (docker or rootless podman) under a single compose file:

| Tool | Role | UI port | Status |
|------------------|--------------------------------------------|---------|---------------------------|
| **syslog-hose** | traffic generator (fills the pipe) | 8080 | shipped (imported from Syshose in S0) |
| **syslog-valve** | visual router/filter on top of syslog-ng | 8081 | shipped: source/filter/forward/cache + retention (S1–S3) |
| **syslog-bucket**| email-client-style syslog server & triage | 8082 | shipped: ingest + triage (S2) — see `apps/syslog-bucket/docs/PLAN.md` |

Each tool works standalone; the suite is composition, not coupling.

## Suite architecture

```
        ┌──────────── yardnet (internal bridge) ────────────┐
        │                                                   │
  syslog-hose ──syslog──▶ syslog-valve ──syslog──▶ syslog-bucket ── postgres
  UI :8080                UI :8081                 UI :8082         (internal only)
                          listeners :514+
                          cache /data + /shares/*
```

- UIs published on **8080 / 8081 / 8082**; all syslog traffic between tools flows over
  the internal bridge by service DNS name (`syslog-valve:514`, `syslog-bucket:514`).
- **Neighbor hints via env**: compose sets `HOSE_SUGGESTED_DEST=syslog-valve:514` and
  `VALVE_SUGGESTED_FORWARD=syslog-bucket:514`; each UI pre-fills its neighbor as the
  default destination. Defaults only — every field stays editable.
- **Cross-navigation**: small shared header in each UI linking to the other two
  (`YARD_LINK_HOSE|VALVE|BUCKET` env — a full URL, or a bare port resolved
  against the browser's current host; hidden when running standalone). Each
  tool serves its deployment hints at `GET /api/hints`.
- Postgres (syslog-bucket's store) gets no published port.
- `deploy/compose.host-net.yaml` override puts syslog-valve on host networking for
  real edge deployments (preserves device source IPs; avoids slirp4netns masking
  under rootless podman — prefer pasta or host-net there).

## External shares (suite-wide)

Any tool that writes log files can target a named **external share** (NAS/NFS/SMB)
in addition to its local `/data` volume.

- **Mounting is the deployment's job, not the app's.** Shares are mounted into
  containers under `/shares/<name>` — via compose named volumes with NFS/CIFS
  `driver_opts`, or (recommended for rootless podman) a bind mount of a share
  already mounted on the host.
- Apps discover shares from env (`YARD_SHARES=archive,nas2` → `/shares/archive`, …),
  validate writability on startup, and expose them in every storage-location picker
  with free-space display and a write-test indicator.
- syslog-valve cache nodes and syslog-bucket retention exports can each point at
  local `/data` or any share. logrotate applies wherever the files land
  (note in docs: compression on NFS is fine; beware locking quirks on CIFS).
- `deploy/compose.yaml` ships a commented NFS and CIFS volume example;
  the full guide is `docs/SHARES.md`.

## Repo layout

```
syslog-yard/
├── apps/
│   ├── syslog-hose/      ← imported from ~/git/syshose with history (git subtree)
│   ├── syslog-valve/
│   └── syslog-bucket/    ← absorbs ~/git/sysbucket plan
├── deploy/
│   ├── compose.yaml             # full suite + commented NFS/CIFS share examples
│   ├── compose.host-net.yaml    # edge override for syslog-valve
│   └── quadlet/                 # rootless podman systemd units
├── docs/
│   └── PLAN.md                  # this file (suite level)
└── README.md
```

## Shared conventions (locked)

- **Go** single binary per tool, **React + TypeScript** UI embedded via `embed`.
- Flat-file persistence in `/data` per tool (Postgres only for syslog-bucket).
- No public API in v1 — UI-only, REST internal.
- One container per tool; images `ghcr.io/…/syslog-hose|valve|bucket`.
- Docs cover docker and rootless podman (quadlet included).

## syslog-valve (the new tool)

A **visual control plane for syslog-ng** — syslog-ng remains the data plane.
Node-graph canvas (React Flow); the backend compiles the graph into
`syslog-ng.conf` + logrotate configs.

**Node palette (v1):**
- **Source (IN)** — bind IP/interface, port, UDP / TCP (RFC 6587) / TLS (RFC 5425)
- **Filter** — facility, severity, host/CIDR, program, message regex (PCRE);
  if/else output ports
- **Forward (OUT)** — destination IP:port, protocol, optional TLS
- **Cache** — file destination to local `/data` or an external share, retention
  knobs (max age, max size, rotate count, compress) compiled to logrotate and run
  by an in-container scheduler
- **Drop** — explicit sink so "filtered out" is visible on the canvas

**Apply pipeline:** graph JSON → generated config → `syslog-ng --syntax-only`
→ atomic swap + `syslog-ng-ctl reload` → last-known-good kept for one-click rollback.

**Observability:** live tail of everything entering the valve, labeled per IN
port (S5: every source duplicates to a unix-dgram tap socket the app streams
over SSE); config errors surfaced in the UI. Still open: per-edge msgs/sec
rendered on the wires from `syslog-ng-ctl stats`.

**Container:** Alpine or Debian-slim bundling syslog-ng, supervised by the Go app.
Graph JSON, generated configs, and version history as flat files in `/data`.

## Milestones

- **S0 — Yard skeleton:** monorepo, import syslog-hose with history (rename
  Syshose → syslog-hose: module, image, UI title), absorb syslog-bucket plan,
  suite compose with syslog-hose + placeholders.
- **S1 — Valve spine:** syslog-ng + Go supervisor container, lifecycle
  (start / syntax-check / reload / rollback), graph model + codegen for plain
  Source → Forward, minimal canvas, Apply end-to-end.
- **S2 — Bucket ingest:** syslog-bucket M1 wired in, so `compose up` gives
  generate → route → store immediately. The suite demo moment.
- **S3 — Valve filtering & cache:** filter nodes, if/else routing, fan-in/out,
  Drop, Cache node + logrotate retention, external-share support across the suite.
- **S4 — Yard cohesion:** cross-UI nav, neighbor-hint env defaults, suite README
  with screenshots, NFS/CIFS share docs.
- **S5 — Ops polish:** TLS in/out on the valve, config version history,
  graph import/export, live tail, GHCR publish, quadlet docs.
- **S6 — Auth & collaboration:** user authentication with local accounts and
  OIDC; collaboration via sharing buckets with different users.
- **S7 — Security review:** review of the code and ensuring the overall
  security posture of the suite.
- **S8 — Sorting & MITRE:** better bucket sorting based on sort keys, device
  class, and additional fields for quick sorting and filtering of syslog
  events. MITRE ATT&CK across the suite: events mapped to techniques at
  ingest, a MITRE view in the bucket with sorting by tactic/technique, and
  a valve filter condition matching MITRE techniques so flows can route or
  drop by technique.
- **S9 — Notifications:** webhooks for notifications and SMTP support.
- **S10 — Clean-up:** code clean-up, more UI hints, and improved
  documentation.

Per-tool detail beyond this lives in each app's own `docs/PLAN.md`
(syslog-bucket's existing plan migrates in S0; syslog-hose's plan comes along with
the subtree import).

## Risks / notes

- Dynamically created valve listeners need reachable ports → host-net override is
  the documented answer for edge use; the internal bridge covers the lab loop.
- syslog-ng reload is graceful for TCP; brief UDP drop during reload is acceptable
  and documented.
- Rootless podman: slirp4netns masks source IPs — document pasta / host networking.
- VM-based runtimes (Rancher/Docker Desktop, Colima) forward TCP but not UDP
  from the host into containers — wire a TCP IN port on the valve for host
  entry there; `yardctl smoke` probes both transports and reports each.
- CIFS file locking can bite logrotate's compress step — document `copytruncate`
  fallback for SMB shares.
