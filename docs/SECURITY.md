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
- **syslog-ng config injection** — the valve never templates raw user
  strings into config; every interpolated value is Go `%q`-quoted, the node
  graph is validated (transport enum, port range, regex compiles, cache dir
  is a relative subpath), and the generated config is run through
  `syslog-ng --syntax-only` before an atomic swap, with last-known-good kept
  for one-click rollback. The child process is exec'd with a fixed argv (no
  shell).
- **Path traversal** — the valve's history endpoints constrain the id to
  `[0-9.\-]`; cache dirs reject `..` and absolute paths; SPA file serving
  cleans the path and stats within the embedded FS.
- **XSS / clickjacking / MIME sniffing** — a Content-Security-Policy
  (`default-src 'self'`, no third-party origins, `frame-ancestors 'none'`),
  plus `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, and
  `Referrer-Policy: no-referrer` on every response from all three tools.
- **Credential handling** — passwords are bcrypt-hashed; session tokens are
  256-bit `crypto/rand`, stored only as their SHA-256, and delivered as
  `HttpOnly`, `SameSite=Lax` cookies. The valve's TLS private key is written
  `0600`.
- **Brute force** — failed logins are throttled per username (10 failures →
  5-minute lockout), keyed by account so it applies even to logins proxied
  through the hose/valve; a correct password clears the counter. A flat
  500 ms delay and a uniform error message avoid a username/password oracle.
- **No shipped default password** — the bucket has no built-in credentials;
  on first start it generates a random admin password and logs it once
  (`BUCKET_ADMIN_PASSWORD` can pin a known one for automated bootstraps).
  `scripts/yardctl reset-admin` rotates it and revokes other sessions.
- **CSRF / cross-origin WebSocket** — state changes are non-GET with
  `SameSite=Lax` cookies (not sent on cross-site POST or WS handshakes), and
  the live-tail WebSocket additionally checks the Origin against the host.
- **Resource exhaustion** — ingest lines are capped (1 MiB), the ingest
  queue has bounded depth with backpressure, slow WebSocket clients drop
  frames rather than stalling ingest, and JSON request bodies are size-
  limited.
- **Privilege escalation** — roles (admin/analyst/viewer) are enforced
  server-side in middleware on every tool, not just hidden in the UI; user
  management requires admin at the bucket regardless of entry point; bucket
  visibility is filtered in SQL so a guessed id can't leak another user's
  saved search; you cannot demote, disable, or delete your own account.

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

## Hardening checklist for production

1. Put all three UIs behind a TLS-terminating reverse proxy; set
   `BUCKET_COOKIE_SECURE=true` and `YARD_COOKIE_SECURE=true`, and add HSTS
   at the proxy.
2. Read the generated admin password from the first-start log (or
   `scripts/yardctl reset-admin` to set a fresh one); give each operator
   their own account with the least role they need.
3. Keep Postgres (`bucket-db`) and the ingest/syslog listeners on the
   internal network only — never publish their ports.
4. Wire OIDC so accounts and MFA live in your IdP; set
   `BUCKET_OIDC_DEFAULT_ROLE=viewer` so new SSO users start read-only.
5. For real syslog sources, use TLS IN ports with proper certificates and
   verified forwarding; mount your CA bundle for peer verification.
6. Restrict who can reach the control-plane ports (firewall/VPN); the data
   plane (syslog) and control plane (UIs) usually want different exposure.
7. Keep base images current (`scripts/yardctl` rebuilds; the Dockerfiles
   pin `golang:1.25` / `node:22` / `postgres:17`).

## Reporting

This is a lab/self-hosted project; file issues for security concerns the
same way as bugs. There is no public deployment to coordinate disclosure
against. If you'd rather report privately (for example, an injection past
one of the defenses above), use GitHub's
[private vulnerability reporting](https://github.com/fqazzazee/syslog-yard/security/advisories/new)
— it's enabled for this repository.
