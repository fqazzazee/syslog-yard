# Syshose — Build Plan

A containerized web app that generates **random-but-realistic syslog events** toward a
user-defined destination IP/port at a configurable rate. Companion tool to
[Sysbucket](../../sysbucket/) — the hose that fills the bucket — but useful against any
syslog collector (SIEM load tests, parser development, lab demos).

## Locked decisions (2026-06-10)

| Decision | Choice |
|---|---|
| Name | **Syshose** (verified collision-free) |
| Backend | **Go**, single static binary |
| Frontend | **React + TypeScript** (Vite), built to static assets, embedded in the Go binary via `embed` |
| Transports | **UDP**, **TCP** (RFC 6587 octet-counting + LF framing), **TLS** (RFC 5425) |
| Wire formats | **RFC 3164** and **RFC 5424** (per-preset default, user-overridable) |
| Concurrency | **Multiple simultaneous jobs**, each with its own preset/destination/rate |
| Persistence | Flat JSON/YAML files in a `/data` volume — **no database** |
| Container | Multi-stage build → distroless/scratch, non-root, single container |
| Distribution | Docker **and** Podman instructions (including rootless + quadlet) |

## Core concepts

### Job
A running generator stream. Fields:

- `name` — display label (e.g. "Edge FortiGate")
- `preset` — built-in or custom template pack
- `destination` — IP/hostname + port
- `transport` — `udp` | `tcp` | `tls` (TLS: optional CA verify / insecure-skip toggle for labs)
- `format` — `rfc3164` | `rfc5424` (defaults from preset)
- `rate` — events per second (fractional allowed, e.g. 0.2 EPS = 1 event / 5 s)
- `rate_mode` — `steady` | `jitter` (±N%) | `burst` (quiet baseline + periodic spikes)
- `duration` — run forever, for N minutes, or until N events sent
- `overrides` — hostname, appname, facility, severity-distribution weights
- `autostart` — start when the container boots (CI / load-test use)

Each job is a goroutine driven by a token-bucket ticker; per-job live counters
(sent, errors, EPS actual, uptime) streamed to the UI via SSE.

### Preset
A template pack describing one appliance's syslog dialect:

- YAML file: metadata (vendor, default format/facility) + a list of **weighted event
  templates** (e.g. FortiGate: 70% traffic-allow, 15% traffic-deny, 10% UTM, 5% VPN).
- Templates use Go `text/template` with helper funcs:
  `{{randIP "rfc1918"}}`, `{{randIP "public"}}`, `{{randPort}}`, `{{randMAC}}`,
  `{{oneOf "admin" "jsmith" "svc-backup"}}`, `{{seq "session"}}`, `{{randInt 64 1500}}`,
  `{{now "Jan _2 15:04:05"}}` (vendor-correct timestamp formats), `{{uuid}}`, `{{hostname}}`.
- Built-ins compiled into the binary **and** a mounted `/data/presets/` dir is scanned at
  startup — users drop in new appliance YAMLs without rebuilding.
- Realism rules: incrementing session/sequence IDs, plausible severity mix, RFC1918
  internals talking to public IPs, consistent per-job hostname/serial.

**v1 preset pack** (each with 4–8 weighted event types):

1. Fortinet FortiGate (key=value: traffic, UTM, VPN, system)
2. Cisco ASA (`%ASA-6-302013/302014`, `106023`, `113019`, …)
3. Palo Alto PAN-OS (CSV TRAFFIC/THREAT/SYSTEM)
4. Check Point
5. Barracuda CloudGen Firewall
6. SonicWall
7. Juniper SRX (structured RT_FLOW)
8. pfSense / OPNsense (`filterlog` CSV)
9. UniFi (UDM firewall, switch, AP events)
10. MikroTik RouterOS
11. Linux host (sshd auth success/fail, sudo, cron, systemd)
12. Windows (Snare/NXLog-forwarded style)
13. OT network gear (Moxa/Hirschmann-style switch events) — OT/ICS lab use
14. Generic RFC 3164 (plain)
15. Generic RFC 5424 (incl. structured-data SD-elements)

### Custom syslog
UI template editor with the same helper syntax + **live preview** ("render 5 samples")
before saving/launching. Saved customs persist to `/data/presets/`.

## Web UI (pages)

1. **Dashboard** — job cards: preset, destination, transport, rate, sent/error counters,
   uptime; start/stop/edit/duplicate/delete; "stop all".
2. **New job wizard** — preset → destination/transport → rate/duration → sample preview → launch.
3. **Preset library** — browse built-ins, view their event templates, clone-to-custom,
   create/edit customs with live preview.
4. **Live tail** — SSE stream showing the last N events a job actually emitted.

REST API is internal (UI-only, like Sysbucket v1): `/api/jobs`, `/api/presets`,
`/api/preview`, `/api/stats`, `/api/events` (SSE).

## Container & deploy

- Multi-stage Dockerfile: `node:22` (UI build) → `golang:1.24` (binary, CGO off) →
  `gcr.io/distroless/static` (or scratch). Target image ≲ 20 MB, runs as non-root,
  listens on **8080**.
- `compose.yaml` with a `/data` volume.
- README quick starts:
  - `docker run -d -p 8080:8080 -v syshose-data:/data ghcr.io/<user>/syshose`
  - `podman run` equivalent + **rootless note** (outbound UDP/TCP needs no privileges;
    we only *send*, never bind 514) + a **quadlet** `.container` unit for systemd.
- Source-IP spoofing is explicitly **out of scope** (needs raw sockets/CAP_NET_RAW);
  multi-device simulation is done via the HOSTNAME field per job instead.

## Testing

- Unit: template helpers, rate limiter accuracy, RFC 6587 framing.
- Integration: spin up an in-test UDP/TCP listener, run a job, parse output back with a
  Go syslog parser lib to assert RFC validity per preset.
- Manual validation target: point at Sysbucket and at syslog-ng.

## Milestones

- **M1 — Core engine**: job runner + rate control, UDP, generic RFC3164/5424 + 3 presets
  (FortiGate, ASA, UniFi), minimal dashboard (create/start/stop/counters), Dockerfile.
- **M2 — Formats & presets**: TCP + TLS transports, full 15-preset pack, custom template
  editor with live preview, live tail.
- **M3 — Ops polish**: `/data` persistence + autostart jobs, jitter/burst rate modes,
  stats/SSE polish, podman/quadlet docs, README badges & GHCR publish workflow.
- **Stretch**: replay mode (feed a real log file, re-emit with rewritten timestamps),
  scenario scripting (timed sequences, e.g. "brute-force then success"), Prometheus
  `/metrics`.
