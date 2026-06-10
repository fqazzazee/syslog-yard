# ⟫⟫ syslog-hose

**A containerized syslog generator with a web UI.** Point the hose at any collector —
a SIEM, [Sysbucket](https://github.com/), syslog-ng, rsyslog, Splunk, Graylog — and it
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
  with automatic reconnection.
- **Rate control** — steady, jitter (±N%), or burst mode (quiet baseline with periodic
  spikes). Fractional rates work too (`0.2` = one event every 5 s). Stop after N seconds
  or N events, or run forever.
- **Live tail** — watch exactly what each job is emitting, in the browser.
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

Or with compose (builds from source):

```bash
git clone <repo-url> && cd syslog-hose
docker compose up -d
```

Open **http://localhost:8080**, create a job, point it at your collector's IP:port, hit ▶.

### Podman

Works rootless out of the box — syslog-hose only makes *outbound* connections and never
binds privileged ports:

```bash
podman build -t syslog-hose .
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

> **Bind mounts:** if you prefer `-v ./data:/data` over a named volume, the directory
> must be writable by uid 65532 (`chown 65532 data`, or on rootless podman:
> `podman unshare chown 65532 data`, or add `:U` to the volume flag).

## Configuration

| Env var        | Default | Meaning                          |
|----------------|---------|----------------------------------|
| `HOSE_ADDR` | `:8080` | Web UI / API listen address      |
| `HOSE_DATA` | `/data` | Jobs + custom presets directory  |
| `YARD_AUTH_URL` | _(unset)_ | Guard the UI with syslog-bucket's accounts (unset = open) |
| `YARD_COOKIE_SECURE` | `false` | Mark session cookies `Secure` (HTTPS) |

Everything else is configured in the UI. State lives in `/data/jobs.json` and
`/data/presets/*.yaml`.

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
| `{{randHex 8}}` | hex string of length n |
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
make build        # builds web UI (node 20+) then the Go binary (go 1.26+)
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

MIT — see [LICENSE](LICENSE).
