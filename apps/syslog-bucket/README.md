# syslog-bucket

An open-source, self-hosted **syslog server + web app modeled on an email
client**. Receive syslog from anything, then sort, filter, tag, and triage
entries the way you triage email. Part of
[syslog-yard](../../README.md); runs standalone too.

**Status: M3 (team)** — everything from M1 (syslog-ng → Go → Postgres
pipeline, generic parser, field + full-text search) and M2 (virtual
**buckets**, color-coded **tags**, a **rules engine** that auto-tags /
sets priority / suppresses at ingest and retroactively, per-entry triage,
**live tail over WebSocket**, 3-pane UI), plus the multi-user layer:
**local accounts + OIDC sign-in**, admin/analyst/viewer roles, and
**bucket sharing** (view-only or can-edit, per user). See
[docs/AUTH.md](../../docs/AUTH.md).

## Quick start

```sh
docker compose -f deploy/docker-compose.yml up --build
```

Open <http://localhost:8080> and sign in (`admin` / the
`BUCKET_ADMIN_PASSWORD` you set, or grab the generated one from the
container log). Then send a test message:

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

## Environment

| Variable                | Default       | Purpose                                  |
|-------------------------|---------------|------------------------------------------|
| `BUCKET_DB_URL`         | local default | Postgres connection string               |
| `BUCKET_API_ADDR`       | `:8080`       | Web UI / API listen address              |
| `BUCKET_INGEST_ADDR`    | `:6601`       | syslog-ng JSON ingest listener (internal) |
| `BUCKET_ADMIN_PASSWORD` | _(generated)_ | initial admin password, first start only |
| `BUCKET_COOKIE_SECURE`  | `false`       | mark session cookies `Secure` (HTTPS)    |
| `BUCKET_OIDC_*`         | _(unset)_     | OIDC SSO — see [docs/AUTH.md](../../docs/AUTH.md) |

## Development

Backend (needs Go 1.25+ and a Postgres):

```sh
go run ./cmd/syslog-bucket
```

Frontend (needs Node 22+; proxies `/api` to `localhost:8080`):

```sh
cd web && npm install && npm run dev
```

## Layout

`cmd/` entrypoint · `internal/` (ingest, parsers, rules, store, auth, api,
ws) · `web/` React SPA · `migrations/` SQL applied at startup · `deploy/`
standalone compose + syslog-ng config.
