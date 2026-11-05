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
  anything:
  - every free-text field rejects control characters (U+0000–001F,
    U+007F–009F, and the U+2028/U+2029 line and paragraph separators) and
    has a length limit (200 bytes for names, 2048 for URLs, 4096 for match
    patterns, 512 for the rest);
  - node IDs must match `[A-Za-z0-9_.-]{1,64}`, and IDs that would compile
    to the same syslog-ng identifier are refused;
  - the transport is an enum, ports are range-checked, regexes must compile;
  - a cache `Dir` must match `^[A-Za-z0-9._/-]+$` with no `..` segment and
    no leading `/`, and a share name `^[A-Za-z0-9._-]+$`;
  - a notify node's URL must be an absolute `http(s)://` URL with a host.

  The generator then quotes defensively as well: strings are `%q`-quoted
  *and* backticks are doubled, because syslog-ng expands backtick
  references everywhere in the config text, inside quoted strings and
  comments included. Comment text is flattened to one line (backticks
  doubled there too). logrotate has no escapes inside quotes, so logrotate
  paths are double-quoted and restricted to a safe character set
  (letters, digits, space and `/._-+@:,=`). Graphs stored by older versions
  (the applied one, history entries) are sanitized on load, control
  characters replaced with spaces, so they can still be opened and rolled
  back to. The generator is fuzz-tested, and integration tests check its
  output against the real `syslog-ng --syntax-only` and logrotate parsers
  (they run where those binaries are installed). Every apply still runs
  `syslog-ng --syntax-only` before an atomic swap and then waits for
  syslog-ng to confirm the reload, restoring the previous config if it
  refuses; last-known-good is kept for one-click rollback, and the child
  process is exec'd with a fixed argv (no shell).
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
  `HttpOnly`, `SameSite=Lax` cookies. A generated admin password carries 128
  bits (16 random bytes, printed as 32 hex characters) and is logged once.
  The valve's TLS private key is written `0600`. Stored secrets stay bound
  to where they are sent: a channel's SMTP password is discarded when its
  kind, host, port, username or TLS mode changes, and the OIDC client
  secret when the issuer changes. An edit that still needs the secret
  answers 400 and asks for it again, so an editor can't redirect a saved
  secret to a server of their choosing. Webhook and Slack/Teams URLs are
  bearer secrets too: viewers see them cut down to scheme and host (with a
  `has_url` flag), and URLs quoted in delivery errors are masked the same
  way.
- **Brute force** — ten failed logins for one (username, client IP) pair
  lock that pair out for 5 minutes, so an attacker can't lock a real user
  out from elsewhere; an account-wide ceiling of 100 failures within 15
  minutes, from all addresses, locks the account for 15 minutes to catch a
  brute force spread over many IPs. Password changes go through the same
  throttle, keyed per user, so a stolen session can't be used to guess the
  real password. Unknown, disabled and SSO-only usernames are compared
  against a dummy bcrypt hash, and every failure gets a flat delay and the
  same message, so neither timing nor wording reveals which usernames
  exist. Logins proxied through the hose/valve carry the real client
  address in `X-Forwarded-For`; the bucket believes that header only from
  peers listed in `YARD_TRUSTED_PROXIES`, so a client can't pick its own
  IP (see [below](#client-addresses-behind-the-hose-valve-or-a-proxy)).
- **OIDC** — the authorization-code flow uses `state`, a `nonce` checked in
  the ID token, and PKCE (`S256`). The public callback page shows only a
  generic failure message; the reason goes to the server log. First-time
  SSO users get the `viewer` role unless `BUCKET_OIDC_DEFAULT_ROLE` (or the
  UI setting) says otherwise.
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
  on each tool. The bucket is stricter still: every POST to its API must be
  `Content-Type: application/json` (415 otherwise), whatever the headers
  say; logout, which has no body, is exempt.
- **Cross-origin WebSocket** — the bucket's live-tail WebSocket accepts
  only same-origin handshakes; add other origins (e.g. a proxy's public
  name, as host patterns like `yard.example.com`) with `BUCKET_WS_ORIGINS`.
  A tail outlives the request that opened it, so it re-checks its session
  every 30 seconds and closes once the session is gone: logout, a password
  change, or an admin disabling, demoting or resetting the account.
- **SSRF via notifications** — every notification delivery (valve notify
  nodes; bucket webhook, Slack/Teams and SMTP channels) goes through one
  outbound guard, `apps/shared/netguard`. HTTP targets are fetched without
  following redirects (a 3xx counts as a failure), and errors carry only the
  status code or the transport error, never the response body or the URL.
  The address is checked after DNS resolution, at connect time: loopback,
  unspecified (`0.0.0.0/8`, `::`), link-local (including cloud metadata at
  `169.254.169.254`) and multicast destinations are refused, and so are the
  `fd00:ec2::254` and `100.100.100.200` metadata addresses. RFC 1918
  addresses are allowed on purpose: on-prem chat, ticketing and mail
  systems live there. `HTTP_PROXY`/`HTTPS_PROXY` is ignored for
  notifications unless `YARD_NOTIFY_PROXY=true` (see the limitation
  below). Bucket SMTP sends are bounded at 20 seconds end to end; mail
  headers are stripped of CR/LF and control characters, so device text
  can't add headers; and the `none` TLS mode never upgrades to STARTTLS
  (`starttls`, the default, upgrades when the server offers it).
- **Resource exhaustion** — ingest lines are capped (1 MiB), the ingest
  queue has bounded depth with backpressure, slow WebSocket clients drop
  frames rather than stalling ingest, and request bodies are size-limited
  (hose: 64 KiB for jobs, 1 MiB for presets and a little more for
  previews; valve: 1 MiB for graphs, 64 KiB for notify tests; oversized JSON
  bodies get a 413). Hose templates are bounded too: `randHex` output at
  1024 characters, a rendered message at 64 KiB, and 256 distinct `seq`
  counters per job. The hose and valve bound header reads at 10 seconds.
  Notification queues are bounded and drop (counting the drops) rather
  than block.
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
- **Configs generated before an upgrade keep running.** The valve restarts
  with the `current.conf` it last applied, and the stricter validation and
  escaping above only apply when a config is generated. A config produced
  by an older version runs until the next Apply, so **re-apply the graph
  after upgrading the valve**.
- **Proxied notifications are checked on a best-effort basis.**
  Notification clients ignore `HTTP_PROXY`/`HTTPS_PROXY` unless
  `YARD_NOTIFY_PROXY=true` is set on the tool. With it, the tool resolves
  each target host itself and refuses it if any address is blocked, before
  handing the request to the proxy; the proxy's own address must be
  allowed too. The proxy resolves the name again, so a name that changes
  its answer between the two lookups can still reach a blocked address as
  seen from the proxy. A target the tool cannot resolve is refused. The
  shipped deployments set no proxy.
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
7. Set `YARD_TRUSTED_PROXIES` on the bucket so the login throttle sees each
   browser's address (see the next section).
8. Keep base images current: `scripts/yardctl up` rebuilds with
   `--pull`, so each run picks up the latest `golang:1.26-alpine`,
   `node:22-alpine`, `alpine:3.22` and distroless base layers, and
   re-pulls `postgres:17-alpine` and `balabit/syslog-ng`. Under quadlet,
   rebuild with `podman build --pull …` (see deploy/quadlet/README.md).
9. Replace the default Postgres password (see below).
10. After upgrading, re-apply the valve's graph so its running config is
    regenerated by the new version (see residual risks).

### Client addresses behind the hose, valve, or a proxy

The login throttle counts failures per (username, client IP). The bucket
takes the client IP from the TCP connection, unless the connection comes
from an address listed in `YARD_TRUSTED_PROXIES` (IPs or CIDRs separated by
commas and/or spaces); then it walks `X-Forwarded-For` from the right, skipping trusted
hops, and uses the first address it doesn't trust. The same list
decides whose `X-Forwarded-Host` the cross-origin guard believes.

Sign-ins made at the hose or valve UI are proxied to the bucket, and the
hose/valve put the browser's address in `X-Forwarded-For`. **If the bucket
doesn't trust them, every login through the hose shares one per-address
budget, and so does every login through the valve**: ten bad passwords for
`admin` from anyone, via the hose, lock `admin` out of the hose's sign-in
for everyone for 5 minutes (sign-in at the bucket itself is unaffected).
Nothing becomes spoofable either way; trusting the proxies restores
per-browser accounting.

Under compose, find the subnet of the yard network:

```sh
docker network inspect syslog-yard_yardnet | grep -i subnet   # or: podman network inspect ...
```

and add it to the `syslog-bucket` service's `environment` in
`deploy/compose.yaml` (there's a commented example), e.g.
`YARD_TRUSTED_PROXIES: "10.89.0.0/24"`, then run `scripts/yardctl up`. Under
quadlet the network is called `yard` (`podman network inspect yard`); add an
`Environment=YARD_TRUSTED_PROXIES=...` line to `syslog-bucket.container`.
With `compose.host-net.yaml` the valve reaches the bucket through its
published port, so the peer the bucket sees is the runtime's port
forwarder rather than the valve. All three tools parse the list the same
way: an entry that is neither an IP nor a CIDR is logged at startup
(`YARD_TRUSTED_PROXIES: ignoring entry …`) and skipped, and the rest of the
list still applies.

Because the walk starts from the right, a reverse proxy in front of the
bucket may append to the header (nginx's usual
`$proxy_add_x_forwarded_for`) or overwrite it; entries a client put there
itself are never reached. The hose and valve overwrite it. If a
reverse proxy sits in front of the hose or valve instead, list it in
*their* `YARD_TRUSTED_PROXIES`, so the address they pass on is the
browser's and not the proxy's.

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
