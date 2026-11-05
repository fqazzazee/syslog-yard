# Notifications

The yard can push alerts off-box. Two complementary places fire them:

- **syslog-bucket** — a rule's **Notify** action alerts on *stored, triaged*
  entries (webhook, Slack/Teams, or SMTP email). Best-effort, off the ingest
  path, so a slow channel never slows ingestion.
- **syslog-valve** — a **Notify** node alerts *in-stream, on the raw flow*,
  before storage (webhook or Slack/Teams). Good for things the valve filters
  out before they ever reach the bucket.

They're complementary, not redundant — the bucket alerts on what it stored and
parsed; the valve alerts on what crosses the wire, filterable by
severity/program/regex/MITRE technique on the spot.

## Channels

Manage channels from the bucket sidebar (**Notifications → ＋**). Each channel
has a kind, kind-specific config, an on/off switch, and a **max/min**
rate cap (0 = unlimited) that guards against alert storms. Analysts and admins
can manage channels; viewers cannot.

| Kind | Delivers | Config |
|------|----------|--------|
| **Webhook (JSON)** | `POST` of `{channel, text, entry}` (the full entry) | endpoint URL |
| **Slack / Teams** | `POST` of `{"text": …}` to an incoming webhook | webhook URL |
| **Email (SMTP)** | a plain-text email | host, port, from, to[], username, password, TLS mode |

SMTP supports **STARTTLS** (port 587, the default; the connection is
upgraded when the server offers it), **implicit TLS** (465), and **none**
(lab only: plain text, never upgraded even if the server offers STARTTLS).
A whole send, from connect to QUIT, is bounded at 20 seconds. The SMTP
**password is write-only**: it is never returned by the API, and leaving it
blank on edit keeps the stored one — unless the edit changes the channel's
kind, host, port, username or TLS mode. Then the stored password is
discarded, and if the new config has a username the save answers 400 and
asks you to re-enter it, so a saved password can't be redirected to another
server.

Webhook and Slack/Teams URLs carry their own secret (anyone holding one can
post to it), so viewers see them cut down to scheme and host (`has_url`
tells the UI one is set), and URLs quoted in delivery errors are masked the
same way.

Use **Send test** on a channel to deliver a synthetic notification and confirm
wiring; the result (and every real delivery) is recorded under **Recent
deliveries** with `ok` / `error` / `dropped` and any error detail. Webhook
errors carry the status code or transport error only, never the response
body or the URL.

A channel can't be deleted while an enabled rule's **Notify** action uses it
(409, naming the rules), and a rule can't name a channel that doesn't exist
(400).

## Firing them from rules

Add a **Notify** action to a rule and pick the channel. Notifications fire
**at ingest only**, when a new entry matches and has been stored — so editing
a rule and running it over history (the retroactive apply) never triggers a
backlog of alerts. The apply-to-history response lists `notify` under
`skipped` to make that explicit. The delivered text is a one-line summary:

```
[crit] fw1 fortigate: applications3: Log4j attack detected … · MITRE T1190
```

Combine with the rest of the rule engine: condition on severity, host, a saved
search, a tag, or a **MITRE technique**, then notify — e.g. "anything
mapped to T1190, page the SOC channel."

## Valve notify node (in-stream)

Add a **Notify** node from the valve palette and wire a filter's `match` (or
`else`) port into it. Matched messages are delivered in real time by the
valve's Go app — syslog-ng duplicates them to an internal datagram socket
tagged with the node, and the dispatcher POSTs them: Slack/Teams get the same
`{"text": …}` as above, and a webhook gets `{source: "syslog-valve", text,
event}`, where `event` holds the message's `time`, `host`, `program`,
`level` and `message`. The node carries its own destination URL (an
absolute `http://` or `https://` URL) and a per-node **max/min** rate cap.
Leaving the cap at 0 or empty means the default of **60/min**; there is no
unlimited setting. **Send test** confirms wiring before you Apply.

Each node has its own worker and a queue of 32 messages, so a slow or dead
endpoint only affects that node and never stalls the socket reader.
Messages over the rate cap or beyond a full queue are dropped and counted;
instead of one log line per drop, the next delivery records a single
`dropped` entry summarizing how many were lost since the previous one.
Recent attempts are kept in memory (`GET /api/notify/log`), and
`GET /api/notify/stats` returns per-node counters since the valve started
(`node`, `ratePerMin`, `sent`, `failed`, `dropped`), keyed by node id.

The valve deliberately offers **webhook and Slack/Teams only, not SMTP**: the
flow graph is inspected, exported, and archived in version history, which is
the wrong place to keep a reusable SMTP password. For email, route the event
to the bucket and use a bucket SMTP channel, where the password is write-only.

## Operational notes

- **Rate limiting** is per channel (bucket) or per node (valve), a sliding
  one-minute window; deliveries beyond the cap are dropped and logged as
  `dropped` rather than queued. A bucket channel's cap of 0 means unlimited;
  a valve node's means 60/min.
- **Backpressure:** the bucket's dispatch queue is bounded (4,096
  deliveries, four workers); if it saturates (a channel is hanging), new
  deliveries are dropped instead of stalling ingest, and the drops are
  written as one summary row per channel and rule every 10 seconds.
- **Shutdown:** the bucket stops ingest first, then gives queued
  deliveries up to 3 seconds; whatever is left is counted as dropped.
- **Outbound safety:** neither tool follows redirects, and both refuse to
  connect to loopback, link-local (including `169.254.169.254`), unspecified
  and multicast addresses, checked after DNS resolution. Private RFC 1918
  addresses are allowed, since that's where on-prem webhook sinks live. An
  `HTTP_PROXY`/`HTTPS_PROXY` in the container's environment would bypass
  that check (only the proxy's address is checked). See
  [SECURITY.md](SECURITY.md).
- The **delivery log** is pruned to the last 7 days automatically.
- Channels reach their endpoints from inside the bucket container — a webhook
  URL must be resolvable on the container's network (use a service name on the
  compose network, or a routable host), and outbound egress must be allowed.
- Secrets (webhook URLs, SMTP credentials) live in the database; protect it and
  serve the UI over TLS (`BUCKET_COOKIE_SECURE`, a reverse proxy) in production.
