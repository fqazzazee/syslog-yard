# syslog-bucket

A self-hosted **syslog server + web app modeled on an email
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

## Web UI

The bucket uses the suite's shared app shell (top bar, tool switcher, side
nav; see [Navigation and deep links](../../README.md#navigation-and-deep-links)),
with violet as its accent colour.

- **Side nav.** Expanded, it lists All Logs, MITRE ATT&CK, ICS/OT Alerts and
  Network, then the frameworks, buckets, tags, rules and (for analysts and
  admins) notification channels, each heading with its add or manage button.
  Collapsed to an icon rail it shows only the sections; on a phone it's a
  drawer. The **Buckets**, **Rules** and **Frameworks** headings open list
  pages (`#/buckets`, `#/rules`, `#/frameworks`).
- **Account menu.** **Account…** and **Sign out** for everyone, **Users…**
  and **Settings…** (single sign-on, session timeout) for admins.
- **Every view is a link:** `#/logs`, `#/buckets/<id>`, `#/tags/<id>`,
  `#/attack[/<technique>]`, `#/ot[/<alert>]`, `#/network`,
  `#/frameworks/<fw>[/<item>]`.
- **Keyboard triage.** In the log table, `j` / `k` or the arrow keys move
  between rows, PageUp / PageDown jump 10 rows, Home / End go to the first
  or last row, Enter (or Space) opens the entry, and Escape closes the
  detail pane. While the pane is open it follows the keyboard selection.
  Column headers are buttons, so sorting works from the keyboard too.
- **Search** takes whole words (ANDed), `or`, `-word` to exclude, and
  `"quoted phrases"` (see [Rules, search, and the API](#rules-search-and-the-api)).
  On narrow screens only the search box shows until you open **Filters**, and
  the log table drops its Pri, Host, App and Class columns as it narrows.
- **Ingest health.** A badge in the page header reads `ingest ok`, the
  number of dropped entries, `ingest backlog N%` (queue 80% full or more), or
  `ingest retrying` (waiting out a database error). Hover it for the
  counters from `GET /api/stats`.

## Environment

| Variable                | Default       | Purpose                                  |
|-------------------------|---------------|------------------------------------------|
| `BUCKET_DB_URL`         | local default | Postgres connection string               |
| `BUCKET_API_ADDR`       | `:8080`       | Web UI / API listen address              |
| `BUCKET_INGEST_ADDR`    | `:6601`       | syslog-ng JSON ingest listener (internal) |
| `BUCKET_ADMIN_PASSWORD` | _(generated)_ | initial admin password, first start only; unset = a random 128-bit password, logged once |
| `BUCKET_COOKIE_SECURE`  | `false`       | mark session cookies `Secure` (HTTPS)    |
| `BUCKET_OIDC_*`         | _(unset)_     | OIDC SSO: `_ISSUER`, `_CLIENT_ID`, `_CLIENT_SECRET`, `_REDIRECT_URL`, `_NAME` (default `SSO`), `_DEFAULT_ROLE` (default `viewer`). See [docs/AUTH.md](../../docs/AUTH.md) |
| `BUCKET_WS_ORIGINS`     | _(unset)_     | extra Origin host patterns (comma-separated, `path.Match` syntax, e.g. `localhost:5173`) allowed to open the live-tail WebSocket; same-origin always works. For development or a proxy that rewrites `Host` |
| `YARD_TRUSTED_PROXIES`  | _(unset)_     | comma-separated IPs/CIDRs whose `X-Forwarded-For` (login throttle) and `X-Forwarded-Host` (cross-origin guard) are believed. See [docs/SECURITY.md](../../docs/SECURITY.md#client-addresses-behind-the-hose-valve-or-a-proxy) |
| `YARD_TRUSTED_ORIGINS`  | _(unset)_     | extra Origins (e.g. `https://yard.example.com`) accepted on state-changing requests, for a reverse proxy that rewrites `Host` |
| `YARD_LINK_HOSE` / `_VALVE` / `_BUCKET` | _(unset)_ | cross-tool nav links: a full URL, or a bare port resolved against the host the browser used |

## Ingest delivery

syslog-ng delivers newline-delimited JSON to `BUCKET_INGEST_ADDR` over TCP.
The bucket batches it into Postgres (up to 500 rows, or every 200 ms) and
aims not to lose what it accepted:

- **Backpressure, not loss.** Accepted records wait in a bounded queue
  (10,000 entries). When the database is down, the batch insert is retried
  with exponential backoff (250 ms doubling to 30 s) for as long as the
  error looks transient. The queue fills, the bucket stops reading the
  socket, and syslog-ng holds the backlog in its own buffers until the
  database is back.
- **One bad row doesn't sink a batch.** If Postgres rejects a batch
  outright, its rows are inserted one at a time; only a row that still
  fails is dropped (and logged).
- **Device text is made storable.** NUL bytes are removed and invalid UTF-8
  is replaced with `�` before insert, since Postgres `text` rejects both.
- **Ordered shutdown.** On SIGTERM the listener closes, open connections get
  1 s to deliver what's already buffered, and the queue drains into the
  database, all within a 6 s budget. Only then does the notification
  dispatcher get up to 3 s for deliveries already queued. Entries still
  unwritten at the deadline are counted as dropped. That can add up to
  about 10 s, the default container stop timeout, so the shipped compose
  and quadlet files give the bucket 30 s.
- Live tail and notifications only see entries that were committed.

`GET /api/stats` includes an `ingest` object with the pipeline counters
since start: `queue_depth`, `queue_capacity`, `inserted`, `failed` (insert
attempts, each retry counts), `dropped`, `bad_records` (unparseable input)
and `retrying` (true while waiting out a database error).

## Rules, search, and the API

- **Free-text search** uses Postgres `websearch_to_tsquery` with the
  `simple` configuration (no stemming, case-insensitive). Words match whole
  words, not substrings, and are ANDed; `"quoted text"` is a phrase; `or`
  between terms means either; a leading `-` excludes a term. Live rules at
  ingest evaluate the same syntax in memory, so a rule and the same search
  in the UI select the same entries.
- **Apply to history** runs a rule over stored entries in a single
  transaction and answers `{affected, matched, skipped}`: entries an action
  changed, entries the condition matched, and the action types that never
  run retroactively. `notify` is always skipped: notifications fire at
  ingest only.
- **Rule references are checked.** Creating or updating a rule whose tag or
  notify action names a tag or channel that doesn't exist answers 400.
  Deleting a tag or channel that an *enabled* rule uses answers 409 with the
  rule names; remove it from those rules, or disable them, first.
- **Default buckets** are seeded once per database (an `app_settings`
  marker, `buckets.seeded`, records it), so deleting them sticks across
  restarts.
- **Session idle timeout:** lowering it also shortens sessions that are
  already open; raising it doesn't extend them.
- **Threat feeds** refresh every 12 h. A failed fetch is retried after 1 min,
  doubling up to 1 h, and the manager checks for stale feeds hourly. An
  admin's refresh (or a save of the network settings) answers 200 with the
  feed status if the fetch finishes within 3 s, otherwise 202
  `{"pending": true}` while it carries on in the background.
- **CSRF:** besides the suite-wide cross-origin guard, every POST to `/api/`
  must be `Content-Type: application/json` (415 otherwise); logout is
  exempt. Clients such as `curl` need `-H 'Content-Type: application/json'`.

## Development

Backend (needs Go 1.26+ and a Postgres):

```sh
go run ./cmd/syslog-bucket
```

Frontend (needs Node 22+; proxies `/api` to `localhost:8080`):

```sh
cd web && npm ci && npm run dev
```

The dev proxy keeps the browser's `Host`, so the live tail and the
cross-origin guard see a same-origin request; `BUCKET_WS_ORIGINS` is only
needed if you point the UI at the backend some other way.

### Tests

`go test ./...` runs the unit tests. The Postgres-backed tests (store,
ingest, migrations, share permissions through the API, and the parity checks
between ingest-time rules and SQL search/apply-to-history) skip themselves
unless `BUCKET_TEST_DSN` points at a server where the role may `CREATE DATABASE`;
each test creates, migrates and drops its own throwaway database
(`internal/store/storetest`):

```sh
podman run -d --rm --name bucket-test-pg -p 55432:5432 \
  -e POSTGRES_PASSWORD=pw docker.io/library/postgres:17-alpine
BUCKET_TEST_DSN=postgres://postgres:pw@localhost:55432/postgres?sslmode=disable go test ./...
podman stop bucket-test-pg
```

CI doesn't set `BUCKET_TEST_DSN`, so these tests only run locally.

## Layout

`cmd/` entrypoint · `internal/` (ingest, parsers, rules, store, auth, api,
ws) · `web/` React SPA · `migrations/` SQL applied at startup · `deploy/`
standalone compose + syslog-ng config.

## License

PolyForm Noncommercial or PolyForm Internal Use, with commercial licenses on
request — see [LICENSE](../../LICENSE) at the repo root. Third-party projects the
suite builds on are credited in [docs/CREDITS.md](../../docs/CREDITS.md).
