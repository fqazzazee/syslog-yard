# syslog-bucket

An open-source, self-hosted **syslog server + web app modeled on an email client**.
Receive syslog from anything, then sort, filter, tag, and assign entries the way you
triage email. See [docs/PLAN.md](docs/PLAN.md) for the full design.

**Status: M2 (email UX)** — everything from M1 (syslog-ng → Go → Postgres
pipeline, generic parser, field + full-text search) plus the email-client
core: virtual **buckets** (saved searches), color-coded **tags**, a **rules
engine** (auto-tag / set-priority / suppress, at ingest and retroactively),
per-entry triage (status + priority), and **live tail over WebSocket** in a
3-pane UI.

## Quick start

```sh
docker compose -f deploy/docker-compose.yml up --build
```

Then open <http://localhost:8080> and send a test message:

```sh
logger -n 127.0.0.1 -P 5514 -T --rfc3164 "hello syslog-bucket"   # TCP (-d for UDP)
# or without logger:
echo '<86>Jun 10 12:00:00 myhost sshd[42]: Accepted password for admin from 10.0.0.5' \
  > /dev/tcp/127.0.0.1/5514
```

Ports (host side, remap in `deploy/docker-compose.yml` as needed):

| Port | Purpose                          |
|------|----------------------------------|
| 8080 | Web UI + internal REST API       |
| 5514 | syslog RFC3164 (UDP + TCP → 514) |
| 5601 | syslog RFC5424 (TCP → 601)       |

> **VM-based Docker (Rancher Desktop, Docker Desktop, Lima):** the VM's port
> forwarder is typically TCP-only, so syslog over **UDP from the host won't
> arrive** even though the mapping is listed. Use TCP (`logger -n 127.0.0.1
> -P 5514 -T …`), or run the stack on a native engine (`podman compose`,
> rootful dockerd) when you need UDP.

## Development

Backend (needs Go 1.24+ and a Postgres):

```sh
go run ./cmd/syslog-bucket    # env: BUCKET_DB_URL, BUCKET_API_ADDR, BUCKET_INGEST_ADDR
```

Frontend (needs Node 22+; proxies `/api` to `localhost:8080`):

```sh
cd web && npm install && npm run dev
```

## Layout

See [docs/PLAN.md §10](docs/PLAN.md) — `cmd/` entrypoint, `internal/`
(ingest, parsers, store, api), `web/` React SPA, `deploy/` compose + syslog-ng
config, `migrations/` SQL.
