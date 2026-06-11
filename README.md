# syslog-yard

One yard, three tools — an open-source, self-hosted syslog toolkit, deployed as
simple containers under a single compose file:

- **syslog-hose** — generates random-but-realistic syslog traffic at a configurable rate
- **syslog-valve** — visual router/filter built on syslog-ng: graphical IN/OUT ports,
  filtering in between, TLS, disk caching with logrotate-managed retention
- **syslog-bucket** — multi-user syslog server and triage UI modeled on an email client

Each tool runs standalone; together they form a complete loop —
generate → route/filter → store — on one internal bridge network, with UIs on
ports 8080 / 8081 / 8082.

## Quick start

```sh
scripts/yardctl prereqs    # fresh system: install container runtime
scripts/yardctl up         # build + start the suite
scripts/yardctl firewall   # open ports (firewalld/ufw, needs sudo)
scripts/yardctl status     # health check; also: down / restart / logs / smoke
```

UIs: hose http://localhost:8080 · valve http://localhost:8081 · bucket
http://localhost:8082 — each UI carries a small **yard** nav linking to the
other two. All three UIs share one sign-in: accounts are defined in the
bucket (the yard's identity provider), and signing in at any UI covers the
others. On first start the bucket creates an `admin` account with a
**random password printed once in its log** — grab it with
`scripts/yardctl logs syslog-bucket | grep -i password`, or set a fresh
one anytime with `scripts/yardctl reset-admin`. See
[docs/AUTH.md](docs/AUTH.md) for users, roles, OIDC single sign-on, and
bucket sharing.

External syslog entry: host port **6514** (udp/tcp) into the valve's IN
ports. Note: VM-based runtimes (Rancher/Docker Desktop, Colima) forward TCP
but not UDP across the VM boundary — `yardctl smoke` probes both and tells
you which arrived.

## The demo loop

The hose streams FortiGate traffic at the valve; the valve forwards
critical/high severities to the bucket and rotates the noise to disk;
the bucket tags and sorts what arrives.

**syslog-hose** — generator jobs built from vendor presets, live tail below:

![syslog-hose](docs/img/syslog-hose.png)

**syslog-valve** — two IN ports feed a severity filter; `match` forwards to
the bucket, `else` caches to disk under logrotate retention:

![syslog-valve](docs/img/syslog-valve.png)

**syslog-bucket** — email-client-style triage of the alerts that got
through, auto-tagged by rules:

![syslog-bucket](docs/img/syslog-bucket.png)

## Documentation

| Doc | Covers |
|-----|--------|
| [docs/AUTH.md](docs/AUTH.md) | bucket sign-in, roles, OIDC, sharing buckets |
| [docs/MITRE.md](docs/MITRE.md) | ATT&CK mapping, the matrix view, sorting, device class, valve technique filter |
| [docs/NOTIFICATIONS.md](docs/NOTIFICATIONS.md) | webhook / Slack-Teams / SMTP channels fired by the notify rule action |
| [docs/SECURITY.md](docs/SECURITY.md) | threat model, what's defended, production hardening checklist |
| [docs/SHARES.md](docs/SHARES.md) | external NAS shares (NFS/CIFS) for log storage |
| [deploy/quadlet](deploy/quadlet) | rootless podman systemd units |
| per-app READMEs | standalone use, env vars, development |

## Features by tool

- **syslog-hose**: vendor presets (FortiGate, Cisco, Linux, …), rate control,
  multiple concurrent jobs, live tail of what it sends.
- **syslog-valve**: node-graph canvas compiled to syslog-ng config with
  syntax check, atomic swap, and one-click rollback; UDP/TCP/TLS listeners
  (one-click self-signed certs); facility/severity/host/program/regex and
  **MITRE ATT&CK technique** filters with if/else routing; disk cache nodes
  with retention compiled to logrotate; **in-stream notify nodes** (webhook,
  Slack/Teams) that alert on the raw flow before storage; live tail of
  everything entering the valve; config version history with previews; graph
  import/export.
- **syslog-bucket**: syslog-ng-fronted ingest into Postgres; email-style
  3-pane triage; virtual buckets (saved searches), color-coded tags, a rules
  engine that tags/prioritizes/suppresses at ingest and retroactively;
  **MITRE ATT&CK mapping at ingest with a kill-chain matrix view**, device-class
  tagging, and sortable/filterable columns; **notifications** (webhook, Slack/
  Teams, SMTP) fired by a notify rule action; live tail over WebSocket; local
  accounts + OIDC sign-in with admin/analyst/viewer roles; buckets shareable
  per-user, view-only or editable.

## Status

S9 complete — notifications ([docs/NOTIFICATIONS.md](docs/NOTIFICATIONS.md)): in
the bucket, a rule's notify action delivers stored entries to webhook,
Slack/Teams, or SMTP channels (off the ingest path, rate-limited, with a
delivery log); in the valve, a notify node alerts in-stream on the raw flow
(webhook / Slack-Teams) before storage. Builds on S8 (MITRE ATT&CK mapping +
matrix view, sorting, device class;
[docs/MITRE.md](docs/MITRE.md)), S7 (security review: threat model, CSP +
hardening headers, login throttling), and S6 (local + OIDC sign-in,
admin/analyst/viewer roles, per-user bucket sharing; the bucket is the yard's
identity provider and the hose and valve share one sign-in). Next: clean-up,
more UI hints, and improved docs (S10).
