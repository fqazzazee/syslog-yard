# Changelog

All notable changes to syslog-yard are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- hose: a job's last error clears once delivery recovers. A single
  reconnect used to leave the card flagged red for the rest of the run; the
  failures still count in `errors`.
- bucket: Barracuda CloudGen entries (`box_Firewall_Activity`,
  `box_Event_eventS`, …) are classified as firewall. The `barracuda` hint
  never matched them, so their device class came out empty.
- hose and valve: every state-changing route caps its request body and
  answers an oversized one with 413 and a JSON error. Hose preset saves over
  1 MiB used to get 400, and the valve capped only graph saves and notify
  tests. Default cap 64 KiB; hose job saves 128 KiB, preset saves and
  previews about 1 MiB, valve graph saves 1 MiB ([#63]).
- bucket: a negated condition (`not`) now matches entries that have no value
  for the field (no facility or source, a missing structured key) in
  searches, buckets and apply-to-history, as rules already did at ingest
  ([#58]).
- bucket: numeric conditions with a fractional or out-of-range value
  (`severity < 2.5`, `facility ≠ 40000`) give the same result in searches and
  apply-to-history as at ingest, instead of being rounded or failing ([#58]).
- bucket: ingest allocates entry ids before inserting a batch instead of
  relying on `RETURNING` order, which Postgres doesn't guarantee ([#58]).
- valve: regenerating the self-signed certificate always leaves the private
  key readable by its owner only, even after an interrupted earlier run
  ([#59]).
- valve and bucket: syslog listeners detect RFC 5424 per message. Before,
  an RFC 5424 line on a valve IN port or the bucket's port 514 was parsed as
  RFC 3164: the app became `1` and the host the sender's address (Check
  Point, Claroty, Juniper and generic-rfc5424 presets). Structured data is
  now kept at the front of the message instead of being dropped by the
  valve's forward. Re-apply the valve flow to pick this up. [#26]
- bucket: FortiGate entries showed App `date=…` and the sender's address as
  Host. A FortiGate parser now sets App `fortigate`, Host from `devname`, and
  keeps `logid`, `devid`, `type`, `subtype` and the other pairs in structured
  fields. SonicWall (`sonicwall`) and PAN-OS CSV (`panos`, with serial, type
  and subtype) logs get the same treatment, and any other headerless
  `key=value` line gets its first pair back instead of losing it to App.
  Already-stored entries keep their old values. [#26]
- bucket: on a fresh database the header showed "~0 entries" while rows
  arrived, because the estimate came from table statistics not yet
  gathered. `/api/stats` now also uses the live-row counter, and counts
  tables under 10,000 rows exactly (`total_exact: true` in the response).
  [#64]
- bucket web: viewers saw rule entries in the nav as disabled buttons titled
  "Edit rule". They now open a read-only **View rule** dialog, also from the
  Rules page ([#64]).
- web: the narrow-screen nav drawer traps Tab and is announced as a modal
  dialog, sharing Dialog's keyboard handling ([#64]).
- web: the bucket served no favicon, and hose and valve only answered
  `/favicon.ico` with their index page. All three ship an SVG favicon in
  their tool color ([#64]).

### Changed

- docs: the README screenshots show the shared shell, taken from a seeded
  demo yard ([#45]).
- bucket: a suppressed entry never notifies. When any matching rule
  suppresses an entry, the notifications queued for it by `notify` actions
  are dropped, whatever the rule and action order. Before, suppressed
  entries still alerted. [#28]
- All tools parse `YARD_TRUSTED_PROXIES` with one shared parser: entries may
  be separated by commas or spaces, and an invalid entry is logged and
  skipped. Before, the bucket accepted commas only and ignored the whole
  list if one entry was invalid. [#62]
- bucket and valve: one outbound guard (`apps/shared/netguard`) for all
  notification delivery. The bucket now also refuses `0.0.0.0/8` and the
  `fd00:ec2::254` and `100.100.100.200` metadata addresses, and applies the
  guard to SMTP channels, which had no address filtering. A loopback or
  link-local SMTP host now fails with "destination address not allowed".
  `HTTP_PROXY`/`HTTPS_PROXY` are no longer used for notifications unless
  `YARD_NOTIFY_PROXY=true`. [#61]
- bucket web: the log table is virtualized, so thousands of entries scroll
  and update smoothly (only the rows near the viewport are rendered). Keyboard
  triage and sortable headers work as before. While scrolled away from the
  top, live arrivals no longer move the view; a **N new** pill counts them
  and scrolls back up ([#57]).
- bucket web: in the collapsed icon rail, tags (as a flyout with **Manage
  tags…**), notification channels and, for admins, the audit log are
  reachable again ([#64]). The header count drops the "~" when the total is
  exact.
- bucket web: the rule editor says next to a notify action that
  notifications fire only as entries arrive, never on **Save + run on
  history**, and that a suppressed entry never notifies ([#28]).

### Added

- hose: TLS jobs can trust a CA bundle or pin the receiver's certificate
  (PEM pasted into the job, checked on save; private keys refused) and
  override the server name the certificate is checked against, so
  `tlsInsecure` is no longer the only way to reach a self-signed receiver.
  A **Trust valve's certificate** button pins syslog-valve's certificate in
  one step: the hose server fetches it from `HOSE_VALVE_URL` (set to
  `http://syslog-valve:8081` in the compose and Quadlet stacks) through the
  hose's `GET /api/valve-cert`. Existing `jobs.json` files load unchanged
  ([#34]).
- valve: `GET /api/certs/pem` serves the public certificate of the TLS IN
  ports (never the key) without a session ([#34]).
- Tests: Postgres-backed bucket tests for entry pagination and sorting,
  insert ids, ingest versus apply-to-history parity (including randomized
  condition trees), migration replay and upgrades, and bucket share
  permissions through the API ([#58]); tests for the bucket's generic parser,
  config and rule engine and the valve's certificate package ([#59]).
- bucket: an audit log ([#27]). Sign-ins (including failures, with the
  username tried), sign-outs and password changes; account, role and
  password-reset changes; OIDC, session and network-feed settings; rule,
  bucket, share, tag, channel and custom-framework edits and rule
  apply-to-history; and entry status, priority, tag and classification
  changes are recorded with the actor, client address and a summary that
  never includes secrets. Admins browse it under **Admin → Audit log**
  (`#/audit`) or `GET /api/audit`. Rows are kept for
  `BUCKET_AUDIT_RETENTION_DAYS` (default 180).
- `YARD_NOTIFY_PROXY=true` (bucket, valve) sends notifications through
  `HTTP_PROXY`/`HTTPS_PROXY`. Each target is resolved and checked against
  the outbound guard before it goes to the proxy. [#61]

## [0.1.1] - 2026-11-05

### Security

Advisories: [GHSA-6g7h-r7gg-27cj] (critical, valve),
[GHSA-hgg5-q44j-49gg], [GHSA-qwhv-2c8j-j2cr], [GHSA-7wq3-v3j7-qhrr] and
[GHSA-rjw7-56hf-frgr]. Upgrade, then re-apply the valve flow.

- All tools: a shared guard rejects cross-origin state-changing API requests.
  Deployments behind a reverse proxy that rewrites `Host` set
  `YARD_TRUSTED_ORIGINS` or `YARD_TRUSTED_PROXIES`.
- bucket: API POSTs must be `application/json`.
- bucket: the live-tail WebSocket accepts same-origin connections only
  (`BUCKET_WS_ORIGINS` adds others), and an open tail closes within 30 s once
  its session is revoked.
- bucket: sessions are revoked when an admin disables, demotes, or resets the
  password of an account.
- bucket: OIDC sign-in uses PKCE and a nonce, shows only a generic error on
  the public callback page, and gives new SSO users the `viewer` role by
  default.
- bucket: stronger brute-force protection: per-(username, client) and
  per-account login throttling, the same throttle on password changes, and
  uniform handling of unknown usernames. The client address is taken from
  `X-Forwarded-For` only when the peer is listed in `YARD_TRUSTED_PROXIES`.
- bucket: generated admin passwords carry 128 bits of entropy.
- bucket: stored SMTP passwords and the OIDC client secret stay bound to the
  server they were entered for, and are discarded when the target changes.
- bucket: webhook and Slack/Teams URLs are masked for viewers.
- bucket and valve: outbound webhook delivery is restricted: no redirects,
  loopback, link-local and similar destinations refused, and no response
  content reflected back.
- bucket: mail headers are sanitized.
- valve: strict validation of graph fields used in generated syslog-ng and
  logrotate configuration, plus defensive escaping in the generator. Configs
  generated by an earlier version keep running until the next Apply, so
  re-apply the graph after upgrading.
- hose and valve: the account proxy builds bucket URLs from validated
  components only.
- hose: request bodies and template output are size-limited; hose and valve
  bound header read time.
- deploy: containers drop capabilities and run with `no-new-privileges`, the
  bucket image runs as a non-root user, and Postgres sits on its own internal
  network.
- bucket: dependency updates for advisories reachable from the store
  (pgx 5.12.0, golang.org/x/text 0.43.0), plus golang.org/x/crypto 0.58.0 and
  go-jose 4.1.6.

### Fixed

- bucket: a race in the notification dispatcher's rate-limiter map could crash
  the process ([#14]).
- bucket: ingest no longer loses entries on shutdown or database errors:
  failed inserts are retried with backoff and push back on syslog-ng, a
  rejected batch falls back to per-row inserts, NUL bytes and invalid UTF-8
  are cleaned up, and shutdown drains the queue ([#15]).
- bucket: deleting a tag or channel used by an enabled rule answers 409, and
  rules referring to unknown tags or channels are refused with 400 ([#16],
  [#29]).
- bucket: notification queue-full drops are summarized instead of costing a
  database write each ([#17]).
- bucket: SMTP delivery is bounded by a 20 s deadline ([#18]).
- bucket: apply-to-history evaluates the condition once and runs in a single
  transaction ([#19]).
- bucket: rule text matching at ingest follows the same websearch semantics
  as the SQL search ([#20]).
- bucket: failed threat-feed fetches are retried with backoff (1 min doubling
  to 1 h), and admin refreshes run in the background ([#21]).
- bucket: the Network view counts an IP listed by several feeds once per
  entry ([#22]).
- bucket: live-tail and webhook payloads include `source_ip` and send empty
  arrays rather than `null` ([#23]).
- bucket: lowering the session idle timeout shortens existing sessions
  ([#24]).
- bucket: default buckets are seeded only once, so deleting them sticks
  ([#25]).
- hose: a second Stop on a job no longer deadlocks the API; Stop is
  idempotent ([#30]).
- hose: the TCP/TLS sender detects closed receivers and resends after a
  reconnect instead of dropping messages ([#31]).
- hose: rate pacing follows elapsed time, so burst and jitter modes deliver
  the configured rate ([#32]).
- hose: `jobs.json` writes are serialized and atomic, so deleted jobs can't
  come back ([#33]).
- hose: live-tail sequence numbers are seeded from the clock, so the UI
  doesn't see duplicate keys after a restart ([#52]).
- valve: Apply waits for syslog-ng to confirm the reload, restores the
  previous config and answers 422 when it is refused ([#35]).
- valve: Rollback regenerates logrotate and notify targets from the archived
  graph and records a new history entry ([#36]).
- valve: notify delivery no longer blocks the socket reader ([#37]).
- valve: node IDs that compile to the same identifier are rejected with a
  clear message ([#38]).
- deploy: standalone per-app image builds work with the `apps/` build context
  ([#39]).
- deploy: `compose.host-net.yaml` points the valve at the bucket's published
  port, so sign-in works ([#40]).
- valve: two forwards to the same host, port and transport (for example a
  filter's match and else branches both feeding the bucket) no longer make
  syslog-ng refuse the config; each gets an explicit persist name.
- deploy: the bucket relay's config mount is relabelled for SELinux hosts
  (Fedora, RHEL), where it previously could not be read.
- Web UI: the bucket filter bar keeps the column sort ([#46]); "Load older"
  can't duplicate or mix rows ([#47]); a failed poll no longer replaces a
  whole view ([#48]); forms don't close when a drag ends on the backdrop
  ([#49]); valve wires stop showing stale rates ([#50]); entry edits report
  errors and can't race ([#51]); live tails backfill after reconnecting and use
  unique keys ([#52]); the valve editor confirms rollback and import, warns
  about unsaved changes and is read-only for viewers ([#53]).
- docs: one place for vulnerability reports ([#41]) and stale statements after
  the shared-module work ([#44]).

### Changed

- valve: a notify node's rate of 0 or empty now means 60 per minute; there is
  no unlimited setting ([#37]).
- valve: two sources may not listen on the same protocol and port, nor on the
  UI's port.
- bucket: the apply-to-history response is `{affected, matched, skipped}`,
  and `notify` is listed as skipped ([#28]).
- bucket: admin feed refresh and network-settings saves answer 202 when the
  fetch takes longer than 3 s.
- All modules, CI and images use Go 1.26 ([#43]).
- deploy: `scripts/yardctl up` pulls fresh base images; `status`, `smoke` and
  `reset-admin` also work with the quadlet units ([#42]).
- deploy: the bucket gets a 30 s stop timeout so shutdown can drain.
- Web UI: hose, valve and bucket share one app shell: a common top bar (tool
  switcher, theme, About & help, an account menu with your name and role), a
  side nav listing every tool's pages that collapses to a rail or a drawer, and
  hash deep links into every page and selection; the bucket's sidebar moved
  into the nav, with list pages for buckets, rules and frameworks, and the
  valve's History became its own page. Text is WCAG AA in both themes, with
  keyboard support (a skip link, focus handling in dialogs, log-table triage
  keys), and all three SPAs run React 19 and Vite 8. Polling
  pauses while a tab is hidden and live-tail updates are batched per frame;
  long tables are not virtualized yet ([#54], [#55], [#56], [#57]).

### Added

- bucket: `GET /api/stats` includes an `ingest` object with pipeline
  counters.
- valve: `GET /api/notify/stats` with per-node counters.
- hose: `GET /api/healthz` and a `syslog-hose healthcheck` subcommand, used by
  the compose and quadlet health checks; the bucket and valve get health
  checks too ([#42]).
- deploy: `YARD_BIND` publishes the UIs on a chosen address, and
  `BUCKET_DB_PASSWORD` sets the Postgres password ([#42]).
- Configuration: `YARD_TRUSTED_ORIGINS`, `YARD_TRUSTED_PROXIES` and
  `BUCKET_WS_ORIGINS`.
- Tests: Postgres-backed bucket tests (run when `BUCKET_TEST_DSN` is set)
  ([#58]), real syslog-ng and logrotate integration tests and fuzzing for the
  valve's generator, and new tests for the hose server, valve server, tap,
  rotate and notify packages and the bucket's route roles ([#59]).

## [0.1.0]

Released under the MIT License; see the commit history for its contents.

[Unreleased]: https://github.com/fqazzazee/syslog-yard/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/fqazzazee/syslog-yard/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/fqazzazee/syslog-yard/releases/tag/v0.1.0
[GHSA-6g7h-r7gg-27cj]: https://github.com/fqazzazee/syslog-yard/security/advisories/GHSA-6g7h-r7gg-27cj
[GHSA-hgg5-q44j-49gg]: https://github.com/fqazzazee/syslog-yard/security/advisories/GHSA-hgg5-q44j-49gg
[GHSA-qwhv-2c8j-j2cr]: https://github.com/fqazzazee/syslog-yard/security/advisories/GHSA-qwhv-2c8j-j2cr
[GHSA-7wq3-v3j7-qhrr]: https://github.com/fqazzazee/syslog-yard/security/advisories/GHSA-7wq3-v3j7-qhrr
[GHSA-rjw7-56hf-frgr]: https://github.com/fqazzazee/syslog-yard/security/advisories/GHSA-rjw7-56hf-frgr
[#14]: https://github.com/fqazzazee/syslog-yard/issues/14
[#15]: https://github.com/fqazzazee/syslog-yard/issues/15
[#16]: https://github.com/fqazzazee/syslog-yard/issues/16
[#17]: https://github.com/fqazzazee/syslog-yard/issues/17
[#18]: https://github.com/fqazzazee/syslog-yard/issues/18
[#19]: https://github.com/fqazzazee/syslog-yard/issues/19
[#20]: https://github.com/fqazzazee/syslog-yard/issues/20
[#21]: https://github.com/fqazzazee/syslog-yard/issues/21
[#22]: https://github.com/fqazzazee/syslog-yard/issues/22
[#23]: https://github.com/fqazzazee/syslog-yard/issues/23
[#24]: https://github.com/fqazzazee/syslog-yard/issues/24
[#25]: https://github.com/fqazzazee/syslog-yard/issues/25
[#26]: https://github.com/fqazzazee/syslog-yard/issues/26
[#27]: https://github.com/fqazzazee/syslog-yard/issues/27
[#28]: https://github.com/fqazzazee/syslog-yard/issues/28
[#29]: https://github.com/fqazzazee/syslog-yard/issues/29
[#30]: https://github.com/fqazzazee/syslog-yard/issues/30
[#31]: https://github.com/fqazzazee/syslog-yard/issues/31
[#32]: https://github.com/fqazzazee/syslog-yard/issues/32
[#33]: https://github.com/fqazzazee/syslog-yard/issues/33
[#34]: https://github.com/fqazzazee/syslog-yard/issues/34
[#35]: https://github.com/fqazzazee/syslog-yard/issues/35
[#36]: https://github.com/fqazzazee/syslog-yard/issues/36
[#37]: https://github.com/fqazzazee/syslog-yard/issues/37
[#38]: https://github.com/fqazzazee/syslog-yard/issues/38
[#39]: https://github.com/fqazzazee/syslog-yard/issues/39
[#40]: https://github.com/fqazzazee/syslog-yard/issues/40
[#41]: https://github.com/fqazzazee/syslog-yard/issues/41
[#42]: https://github.com/fqazzazee/syslog-yard/issues/42
[#43]: https://github.com/fqazzazee/syslog-yard/issues/43
[#44]: https://github.com/fqazzazee/syslog-yard/issues/44
[#45]: https://github.com/fqazzazee/syslog-yard/issues/45
[#46]: https://github.com/fqazzazee/syslog-yard/issues/46
[#47]: https://github.com/fqazzazee/syslog-yard/issues/47
[#48]: https://github.com/fqazzazee/syslog-yard/issues/48
[#49]: https://github.com/fqazzazee/syslog-yard/issues/49
[#50]: https://github.com/fqazzazee/syslog-yard/issues/50
[#51]: https://github.com/fqazzazee/syslog-yard/issues/51
[#52]: https://github.com/fqazzazee/syslog-yard/issues/52
[#53]: https://github.com/fqazzazee/syslog-yard/issues/53
[#54]: https://github.com/fqazzazee/syslog-yard/issues/54
[#55]: https://github.com/fqazzazee/syslog-yard/issues/55
[#56]: https://github.com/fqazzazee/syslog-yard/issues/56
[#57]: https://github.com/fqazzazee/syslog-yard/issues/57
[#58]: https://github.com/fqazzazee/syslog-yard/issues/58
[#59]: https://github.com/fqazzazee/syslog-yard/issues/59
[#61]: https://github.com/fqazzazee/syslog-yard/issues/61
[#62]: https://github.com/fqazzazee/syslog-yard/issues/62
[#63]: https://github.com/fqazzazee/syslog-yard/issues/63
[#64]: https://github.com/fqazzazee/syslog-yard/issues/64
