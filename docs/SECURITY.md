# Security posture

This is the security review of syslog-yard: the trust boundaries, what the code
defends against today, the residual risks you accept by running it, and a
checklist for hardening a real deployment. Authentication mechanics live in
[AUTH.md](AUTH.md); this document is about the threat model.

## Trust boundaries

```
   syslog devices ──udp/tcp/tls──▶ valve IN ports ─┐         operators ──https?──▶ UIs :8080/1/2
   (untrusted wire data)                           │                              (authenticated)
                                                    ▼
                                          syslog-ng (valve) ──▶ bucket ingest :6601 ──▶ Postgres
                                                                 (internal, unauthenticated)
```

Two distinct planes:

- **Data plane** — syslog traffic. Untrusted by definition (anything on the
  network can send a packet). It never reaches a shell or a query builder
  unescaped: syslog-ng parses the wire, the bucket ingests structured JSON
  into **parameterized** inserts, and message text is stored as data and
  rendered as React text nodes (auto-escaped), so a hostile log line can't
  inject SQL or script.
- **Control plane** — the three web UIs and their REST APIs. Authenticated:
  the bucket is the identity provider, the hose and valve verify the
  shared session against it. This is the plane that mutates state (jobs,
  flow graphs, triage, users).

The boundary between them is one-way: operators configure the data plane
through the control plane, but wire data only ever flows *into* storage,
never back into config or commands.

## What the code defends against

- **SQL injection** — every query is parameterized through pgx. The shared
  condition AST (`internal/rules`) compiles to placeholder-bound SQL only;
  field names are whitelisted against a fixed map and `structured.<key>`
  lookups bind the key as a value, never as identifier text.
- **syslog-ng / logrotate config injection** — quoting alone isn't the
  defence (a Go `%q` string is not a syslog-ng string: escapes and newlines
  differ), so the valve validates the graph strictly before generating
  anything: control characters are rejected in every free-text field, node
  IDs are restricted to a safe identifier charset, the transport is an enum,
  ports are range-checked, regexes must compile, and a cache `Dir` must
  match `[A-Za-z0-9._/-]` with no `..` and no leading `/`. Comment text is
  sanitized before it lands in a `#` line, and logrotate paths are quoted.
  The generator is fuzz-tested, and its output is checked against the real
  `syslog-ng --syntax-only` and logrotate parsers. Every apply still runs
  `syslog-ng --syntax-only` before an atomic swap, with last-known-good
  kept for one-click rollback; the child process is exec'd with a fixed
  argv (no shell).
- **Path traversal** — the valve's history endpoints constrain the id to
  `[0-9.\-]`; cache dirs are whitelisted as above; SPA file serving cleans
  the path and stats within the embedded FS. The hose/valve account proxy
  builds the bucket URL from fixed paths and a numeric user id, never from
  the (decoded) request path, so `..%2F` can't steer it to another bucket
  endpoint.
- **XSS / clickjacking / MIME sniffing** — a Content-Security-Policy
  (`default-src 'self'`, no third-party origins, `frame-ancestors 'none'`),
  plus `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, and
  `Referrer-Policy: no-referrer` on every response from all three tools.
- **Credential handling** — passwords are bcrypt-hashed; session tokens are
  256-bit `crypto/rand`, stored only as their SHA-256, and delivered as
  `HttpOnly`, `SameSite=Lax` cookies. The valve's TLS private key is written
  `0600`. A stored SMTP password is discarded when a notification channel's
  target (SMTP server or account) changes, so editing the target can't
  redirect the saved secret to a server of the editor's choosing.
- **Brute force** — failed logins are throttled per (username, client IP),
  so an attacker can't lock a real user out from elsewhere, and password
  changes are throttled too. Logins proxied through the hose/valve carry
  the real client address in `X-Forwarded-For`; the bucket believes that
  header only from peers it is configured to trust as proxies, so a client
  can't pick its own IP. A flat delay and a uniform error message avoid a
  username/password oracle.
- **OIDC** — the authorization-code flow uses `state`, a `nonce` checked in
  the ID token, and PKCE. First-time SSO users get the `viewer` role unless
  `BUCKET_OIDC_DEFAULT_ROLE` (or the UI setting) says otherwise.
- **No shipped default password** — the bucket has no built-in credentials;
  on first start it generates a random admin password and logs it once
  (`BUCKET_ADMIN_PASSWORD` can pin a known one for automated bootstraps).
  `scripts/yardctl reset-admin` rotates it and revokes other sessions.
- **CSRF / cross-origin requests** — `SameSite=Lax` is not enough on its
  own: every port of one host (`localhost:3000`, `:8080`, `:8082`) is the
  same *site*, so any other web app on the lab host could otherwise post to
  a yard API with the user's cookie. A shared guard on all three tools
  (`apps/shared/secure`) therefore checks every POST/PUT/PATCH/DELETE:
  `Sec-Fetch-Site: cross-site`/`same-site` is rejected; a present `Origin`
  must match the request's host (scheme-agnostic, so a TLS-terminating
  proxy that keeps `Host` works); and a body that isn't JSON — the
  `text/plain`, form and multipart types a browser can send cross-origin
  without a CORS preflight — needs positive same-origin proof
  (`Sec-Fetch-Site: same-origin` or a matching `Origin`). Clients that send
  neither header (curl, `yardctl`, the hose/valve account proxy) keep
  working with JSON or empty bodies. Behind a reverse proxy that rewrites
  `Host`, list the public origin in `YARD_TRUSTED_ORIGINS`
  (e.g. `https://yard.example.com`), or list the proxy's address in
  `YARD_TRUSTED_PROXIES` so its `X-Forwarded-Host` is believed — set them
  on each tool.
- **Cross-origin WebSocket** — the bucket's live-tail WebSocket accepts
  only same-origin handshakes; add other origins (e.g. a proxy's public
  name) with `BUCKET_WS_ORIGINS`.
- **SSRF via notifications** — webhook/Slack/Teams targets (valve notify
  nodes and bucket channels) are fetched without following redirects,
  their response bodies are never echoed back to the UI, and loopback and
  link-local destinations (including cloud metadata at `169.254.169.254`)
  are blocked. RFC 1918 addresses are allowed on purpose: on-prem chat and
  ticketing systems live there.
- **Resource exhaustion** — ingest lines are capped (1 MiB), the ingest
  queue has bounded depth with backpressure, slow WebSocket clients drop
  frames rather than stalling ingest, and JSON request bodies are size-
  limited.
- **Privilege escalation** — roles (admin/analyst/viewer) are enforced
  server-side in middleware on every tool, not just hidden in the UI; user
  management requires admin at the bucket regardless of entry point; bucket
  visibility is filtered in SQL so a guessed id can't leak another user's
  saved search; you cannot demote, disable, or delete your own account.
- **Container privileges** — the hose (distroless) and the bucket run as
  non-root users with every capability dropped. The valve stays root inside
  its container, because syslog-ng binds the listeners you draw (514
  included) and existing `valve-data` volumes are root-owned, but it keeps
  only `NET_BIND_SERVICE`, `CHOWN`, `DAC_OVERRIDE` and `FOWNER` (for cache
  files on shares owned by another uid). All three run with
  `no-new-privileges`. Postgres sits on its own internal network that only
  the bucket joins.

## Residual risks (accept, or mitigate per the checklist)

- **HTTP by default.** The suite serves plain HTTP for the localhost lab
  flow; cookies are only marked `Secure` when you opt in
  (`BUCKET_COOKIE_SECURE`/`YARD_COOKIE_SECURE=true`). Without TLS, sessions
  and passwords cross the wire in clear. Terminate TLS at a reverse proxy
  for any real deployment.
- **Unauthenticated ingest.** The bucket's ingest listener (`:6601`) and the
  valve's syslog IN ports trust their network — they have no per-sender
  auth beyond optional TLS. Keep ingest internal (it is not published by
  compose) and treat stored log content as untrusted input.
- **No audit log yet.** Who changed which rule/bucket/user is not recorded
  (planned in the bucket's M4). Roles limit *who can*, but actions aren't
  attributed after the fact.
- **Self-signed valve TLS.** The one-click cert is for lab use; forwarding
  in lab mode uses `peer-verify(optional-untrusted)`. Use real certificates
  and verified forwarding (the node's "verify peer" option) in production.
- **Single workspace.** v1 is single-tenant (the `org_id` columns are
  reserved but unused); every analyst shares one tag/rule namespace.
- **Static default database password.** For compatibility with existing
  volumes, Postgres still defaults to the password `syslog_bucket`. It is
  reachable only from the bucket's container on an internal network, but
  set your own (below) for anything beyond a lab.

## Hardening checklist for production

1. Put all three UIs behind a TLS-terminating reverse proxy; set
   `BUCKET_COOKIE_SECURE=true` and `YARD_COOKIE_SECURE=true`, and add HSTS
   at the proxy.
2. Read the generated admin password from the first-start log (or
   `scripts/yardctl reset-admin` to set a fresh one); give each operator
   their own account with the least role they need.
3. Keep Postgres (`bucket-db`) and the ingest/syslog listeners on the
   internal network only — never publish their ports.
4. Wire OIDC so accounts and MFA live in your IdP; new SSO users start as
   `viewer` (read-only) — keep that default and promote people explicitly.
5. For real syslog sources, use TLS IN ports with proper certificates and
   verified forwarding; mount your CA bundle for peer verification.
6. Restrict who can reach the control-plane ports (firewall/VPN); the data
   plane (syslog) and control plane (UIs) usually want different exposure.
   On a single-host lab, `YARD_BIND=127.0.0.1` (in `deploy/.env`) publishes
   the three UIs on loopback only; the syslog port 6514 is unaffected.
   Behind a reverse proxy, set `YARD_TRUSTED_ORIGINS` (or
   `YARD_TRUSTED_PROXIES`) on each tool and `BUCKET_WS_ORIGINS` on the
   bucket — see the CSRF entry above.
7. Keep base images current: `scripts/yardctl up` rebuilds with
   `--pull`, so each run picks up the latest `golang:1.26-alpine`,
   `node:22-alpine`, `alpine:3.22` and distroless base layers, and
   re-pulls `postgres:17-alpine` and `balabit/syslog-ng`. Under quadlet,
   rebuild with `podman build --pull …` (see deploy/quadlet/README.md).
8. Replace the default Postgres password (see below).

### Changing the Postgres password

`BUCKET_DB_PASSWORD` sets both Postgres's password and the bucket's
connection string; it defaults to the historical `syslog_bucket`. Postgres
only reads it when the `bucket-dbdata` volume is first initialised, so on a
fresh install setting it in `deploy/.env` before the first
`scripts/yardctl up` is enough. To rotate it on an existing volume, change
it inside Postgres first, then tell compose:

```sh
NEW=$(openssl rand -hex 24)   # keep it URL-safe: it goes into a DSN
docker compose -f deploy/compose.yaml exec -T bucket-db \
  psql -U syslog_bucket -d syslog_bucket -c "ALTER ROLE syslog_bucket PASSWORD '$NEW'"
echo "BUCKET_DB_PASSWORD=$NEW" >> deploy/.env   # replace any earlier line
scripts/yardctl up                               # recreates the bucket with the new DSN
```

(Use `podman compose`/`podman-compose` in place of `docker compose` as
appropriate. Under quadlet: `podman exec -i bucket-db psql …`, then edit
`POSTGRES_PASSWORD` in `bucket-db.container` and `BUCKET_DB_URL` in
`syslog-bucket.container`, `systemctl --user daemon-reload` and restart
both.) The local socket inside the container trusts `psql`, so the old
password isn't needed; `deploy/.env` holds a secret now, so `chmod 600` it.

## Reporting

Don't open a public issue for a vulnerability. Follow the
[security policy](../SECURITY.md): report it through GitHub's
[private vulnerability reporting](https://github.com/fqazzazee/syslog-yard/security/advisories/new)
(enabled for this repository) or by email.
