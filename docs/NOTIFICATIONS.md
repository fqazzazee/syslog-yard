# Notifications

S9 lets syslog-bucket push alerts off-box: a rule's **Notify** action delivers
matching entries to a **channel** — a generic webhook, a Slack/Teams incoming
webhook, or email over SMTP. Delivery is best-effort and runs off the ingest
path, so a slow or failing channel never slows ingestion.

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

SMTP supports **STARTTLS** (port 587, the default), **implicit TLS** (465),
and **none** (lab only). The SMTP **password is write-only**: it is never
returned by the API, and leaving it blank on edit keeps the stored one.

Use **Send test** on a channel to deliver a synthetic notification and confirm
wiring; the result (and every real delivery) is recorded under **Recent
deliveries** with `ok` / `error` / `dropped` and any error detail.

## Firing them from rules

Add a **Notify** action to a rule and pick the channel. Notifications fire
**at ingest only**, when a new entry matches — so editing a rule and running it
over history (the retroactive apply) never triggers a backlog of alerts. The
delivered text is a one-line summary:

```
[crit] fw1 fortigate: applications3: Log4j attack detected … · MITRE T1190
```

Combine with the rest of the rule engine: condition on severity, host, a saved
search, a tag, or a **MITRE technique** (S8), then notify — e.g. "anything
mapped to T1190, page the SOC channel."

## Operational notes

- **Rate limiting** is per channel, a sliding one-minute window; deliveries
  beyond the cap are dropped and logged as `dropped` rather than queued.
- **Backpressure:** the dispatch queue is bounded; if it saturates (a channel
  is hanging), new deliveries are dropped (logged) instead of stalling ingest.
- The **delivery log** is pruned to the last 7 days automatically.
- Channels reach their endpoints from inside the bucket container — a webhook
  URL must be resolvable on the container's network (use a service name on the
  compose network, or a routable host), and outbound egress must be allowed.
- Secrets (webhook URLs, SMTP credentials) live in the database; protect it and
  serve the UI over TLS (`BUCKET_COOKIE_SECURE`, a reverse proxy) in production.
