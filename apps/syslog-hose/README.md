# ⟫⟫ syslog-hose

**A containerized syslog generator with a web UI.** Point the hose at any collector —
a SIEM, [syslog-bucket](../syslog-bucket/README.md), syslog-ng, rsyslog, Splunk, Graylog — and it
sprays *random-but-realistic* syslog events at whatever rate you ask for. Built for
testing parsers, load-testing pipelines, demos, and lab work.

## Features

- **Realistic appliance presets** — 15 built-ins: Fortinet FortiGate, Cisco ASA,
  Palo Alto PAN-OS, Check Point, Barracuda CloudGen, SonicWall, Juniper SRX,
  pfSense/OPNsense, UniFi, MikroTik, Linux hosts, Windows (Snare format), industrial
  OT switches, and generic RFC 3164 / RFC 5424. Each is a weighted mix of event types
  (traffic allows/denies, UTM blocks, auth events, link flaps…) with plausible IPs,
  ports, usernames, session counters and vendor-correct timestamps.
- **Custom presets** — define your own appliance format in the UI with a template
  language and live preview, or drop YAML files into `/data/presets/`.
- **Multiple simultaneous jobs** — run a FortiGate at 50 EPS to host A while a
  Cisco ASA does 10 EPS to host B. Per-job live counters and actual-EPS readout.
- **Transports** — UDP, TCP (RFC 6587 octet-counted framing), TLS (RFC 5425),
  with automatic reconnection (see [Delivery over TCP/TLS](#delivery-over-tcptls)).
- **Rate control** — steady, jitter (±N%), or burst mode (quiet baseline with periodic
  spikes). Fractional rates work too (`0.2` = one event every 5 s). Stop after N seconds
  or N events, or run forever. Pacing follows elapsed time, so the long-run rate
  matches the setting; the configured rate, and the effective rate after jitter or
  burst multipliers, are capped at 50,000 events/s.
- **Live tail** — watch exactly what each job is emitting, in the browser.
- **The shared yard UI** — Jobs (`#/jobs`), Presets (`#/presets`, or
  `#/presets/<name>` for one preset) and Live tail (`#/tail`) are pages of the
  suite's app shell, so the other tools can link straight to them (see
  [Navigation and deep links](../../README.md#navigation-and-deep-links)). The
  Jobs entry in the side nav shows how many jobs are running, and a collapsible
  tail sits under the job cards (closed by default on phones).
- **Boring ops** — one ~20 MB container, no database, runs as non-root, config
  persists as flat files in one volume, jobs marked *autostart* resume on boot.

## Quick start

### Docker

```bash
docker run -d --name syslog-hose \
  -p 8080:8080 \
  -v syslog-hose-data:/data \
  syslog-hose:latest
```

Or with compose (builds from source; the build context is the parent `apps/`
dir because the image also copies `apps/shared`):

```bash
git clone <repo-url> && cd syslog-yard/apps/syslog-hose
docker compose up -d --build
```

Open **http://localhost:8080**, create a job (**New job**), point it at your collector's IP:port, and press **Start**.

### Podman

Works rootless out of the box — syslog-hose only makes *outbound* connections and never
binds privileged ports:

```bash
# context is the parent apps/ dir: the image also copies apps/shared
# (same as `make image`)
podman build -t syslog-hose -f Dockerfile ..
podman run -d --name syslog-hose \
  -p 8080:8080 \
  -v syslog-hose-data:/data \
  syslog-hose
```

To run it as a systemd service with quadlet, create
`~/.config/containers/systemd/syslog-hose.container`:

```ini
[Unit]
Description=syslog-hose syslog generator

[Container]
Image=localhost/syslog-hose:latest
PublishPort=8080:8080
Volume=syslog-hose-data:/data

[Service]
Restart=always

[Install]
WantedBy=default.target
```

then `systemctl --user daemon-reload && systemctl --user start syslog-hose`.

The image has no shell or `wget`, so health checks run the binary itself:
`syslog-hose healthcheck` probes the local `GET /api/healthz` (unauthenticated)
and exits non-zero on failure. Add `HealthCmd=["/syslog-hose", "healthcheck"]`
to the unit above, or `test: ["CMD", "/syslog-hose", "healthcheck"]` under
compose, as the suite's own files do.

> **Bind mounts:** if you prefer `-v ./data:/data` over a named volume, the directory
> must be writable by uid 65532 (`chown 65532 data`, or on rootless podman:
> `podman unshare chown 65532 data`, or add `:U` to the volume flag).

## Configuration

| Env var        | Default | Meaning                          |
|----------------|---------|----------------------------------|
| `HOSE_ADDR` | `:8080` | Web UI / API listen address (the `healthcheck` subcommand probes it too) |
| `HOSE_DATA` | `/data` | Jobs + custom presets directory  |
| `HOSE_SUGGESTED_DEST` | _(unset)_ | Default destination (`host:port`) pre-filled for new jobs |
| `HOSE_VALVE_URL` | _(unset)_ | syslog-valve API base URL as reachable from the hose (e.g. `http://syslog-valve:8081`); enables **Trust valve's certificate** ([TLS verification](#tls-verification)) |
| `YARD_AUTH_URL` | _(unset)_ | Guard the UI with syslog-bucket's accounts (unset = open) |
| `YARD_COOKIE_SECURE` | `false` | Mark session cookies `Secure` (HTTPS) |
| `YARD_TRUSTED_ORIGINS` | _(unset)_ | Extra Origins accepted on state-changing requests, for a reverse proxy that rewrites `Host` |
| `YARD_TRUSTED_PROXIES` | _(unset)_ | IPs/CIDRs of a reverse proxy in front of the hose: its `X-Forwarded-Host` and `X-Forwarded-For` are believed ([docs/SECURITY.md](../../docs/SECURITY.md)) |
| `YARD_LINK_HOSE` / `_VALVE` / `_BUCKET` | _(unset)_ | Cross-tool nav links: a full URL, or a bare port resolved against the host the browser used |

Everything else is configured in the UI. State lives in `/data/jobs.json` and
`/data/presets/*.yaml`. `jobs.json` is written atomically (temp file, fsync,
rename), so a crash or power cut leaves either the old or the new version.

## Delivery over TCP/TLS

Plain syslog over TCP has no acknowledgements, so a sender can't know what a
receiver actually read. The hose narrows the gap:

- Before each write it checks whether the receiver has closed the connection
  (FIN, RST, or a TLS close_notify) and reconnects instead of writing into a
  dead socket.
- If a write fails, the same frame is sent once more on a fresh connection
  right away.
- Only if that fails too does the job back off: 250 ms, doubling to 5 s, with
  jitter. Messages generated during the backoff count as errors.

What can still be lost: frames already written into a receiver's socket
buffer when it closes without reading them (a restart of the collector,
say). Use a protocol with acknowledgements downstream if every message
matters.

## TLS verification

A TLS job verifies the receiver's certificate against the system roots by
default. A lab receiver with a private CA or a self-signed certificate (such
as syslog-valve's) needs one of the job's TLS settings:

- **Trusted CA or certificate** (`tlsCA` in `jobs.json`): PEM text with one
  or more certificates. A CA bundle trusts what that CA signed; the
  receiver's own certificate pins it (a self-signed certificate is its own
  root). Saving checks the PEM; a private key is refused, so never paste
  one. The host name is still checked against the certificate.
- **Server name** (`tlsServerName`): the name the certificate is checked
  against, when it differs from the destination host. Example: sending to
  `10.0.0.5` when the certificate names `syslog-valve`.
- **Skip certificate verification** (`tlsInsecure`): no check at all. Lab
  use only, and it can't be combined with a trusted certificate.

Jobs saved before these fields existed load unchanged.

**Trust valve's certificate.** With `HOSE_VALVE_URL` set (the compose stack
sets `http://syslog-valve:8081`), the job form offers a button that pins
the valve's certificate in one step. The hose server fetches it from the
valve's `GET /api/certs/pem`, which serves the public certificate only and
needs no session. The browser can't fetch it directly, because the UI's CSP
allows same-origin requests only. The hose's own endpoint is
`GET /api/valve-cert`, answering `{"pem", "subject", "notAfter", "names"}`.
Generate the valve's certificate first (TLS IN node, **Generate self-signed
cert**) and send to a name it covers (`syslog-valve`, `localhost`,
`127.0.0.1` or the valve's host name). The fetch runs over the plain-HTTP
API inside the yard network, so it trusts that network the way first use of
any self-signed certificate does. If the valve regenerates its certificate,
pin it again. Without `HOSE_VALVE_URL`, copy the valve's `/data/certs/valve.crt`
into the field by hand.

## Jobs and limits

- **Stop is idempotent.** Stopping a job that is idle or already stopping is
  a no-op; a stop waits up to 10 s for the job to wind down. Starting a job
  that is still stopping returns an error ("job is still stopping, try
  again").
- **Request bodies** are capped on every state-changing route: job
  create/update at 128 KiB (room for a CA bundle of up to 64 KiB), preset
  saves at 1 MiB, previews at about 1 MiB (a whole preset plus the job), and
  everything else at 64 KiB. An oversized body gets **413** with
  `{"error": "..."}`.
- **Templates** are bounded: `randHex` returns at most 1024 characters, a
  rendered message may be at most 64 KiB (the job reports an error past
  that), and a job keeps at most 256 distinct `seq` counter names (a further
  name gets a random number instead of a counter).

## Writing a custom preset

A preset is a YAML file: metadata plus a list of **weighted event templates**.
Weights set how often each event type appears; severity sets the syslog PRI.

```yaml
name: my-appliance
vendor: MyVendor
description: What this device's logs look like
format: rfc3164      # rfc3164 | rfc5424 | raw ("<PRI>" + template as-is)
facility: 16         # 0-23 (16 = local0)
appname: myapp
events:
  - weight: 80
    severity: 6
    template: >-
      user={{oneOf "alice" "bob"}} src={{randIP "rfc1918"}}:{{randPort}}
      dst={{randIP "public"}}:443 action=allow session={{seq "session"}}
  - weight: 20
    severity: 4
    template: >-
      action=deny src={{randIP "public"}} dst={{randIP "rfc1918"}} port={{randInt 1 1024}}
```

Template helpers:

| Helper | Output |
|---|---|
| `{{randIP "rfc1918"}}` / `{{randIP "public"}}` / `{{randIP "any"}}` | plausible IPv4 |
| `{{randPort}}` | ephemeral port 1024–65535 |
| `{{randMAC}}` | locally-administered MAC |
| `{{randInt 10 99}}` | integer in range (inclusive) |
| `{{randHex 8}}` | hex string of length n (at most 1024) |
| `{{oneOf "a" "b" "c"}}` | random pick |
| `{{seq "name"}}` | named per-job incrementing counter (random start) |
| `{{now "2006-01-02 15:04:05"}}` | event time in any [Go layout](https://pkg.go.dev/time#pkg-constants) |
| `{{uuid}}` | random UUIDv4 |
| `{{hostname}}` / `{{appname}}` | the job's identity fields |

Per-event `appname:` overrides the preset's (e.g. Linux `sshd` vs `sudo` vs `CRON`).
Jobs can override the HOSTNAME/APP-NAME fields and wire format, so one preset can
simulate a whole fleet of differently named devices.

## Building from source

```bash
make build        # builds web UI (node 22+) then the Go binary (go 1.26+)
make test         # go test ./...
HOSE_DATA=./data ./syslog-hose
```

The REST API under `/api` is internal and unversioned — the UI is the supported
interface for now.

## Scope notes

- Spoofing **source IPs** is intentionally out of scope (it needs raw sockets and
  CAP_NET_RAW). To simulate many devices, run several jobs with different HOSTNAME
  fields — collectors key on the header hostname anyway.
- syslog-hose generates *load and shape*, not attack content. Event payloads are
  fictional (RFC 1918 internals, documentation-style URLs, invented users).

## License

PolyForm Noncommercial or PolyForm Internal Use, with commercial licenses on
request — see [LICENSE](../../LICENSE) at the repo root. Third-party projects the
suite builds on are credited in [docs/CREDITS.md](../../docs/CREDITS.md).
