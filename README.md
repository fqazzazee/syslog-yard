# syslog-yard

One yard, three tools — an open-source, self-hosted syslog toolkit, deployed as
simple containers under a single compose file:

- **syslog-hose** — generates random-but-realistic syslog traffic at a configurable rate
- **syslog-valve** — visual router/filter built on syslog-ng: graphical IN/OUT ports,
  filtering in between, disk caching with logrotate-managed retention
- **syslog-bucket** — syslog server and triage UI modeled on an email client

Each tool runs standalone; together they form a complete loop —
generate → route/filter → store — on one internal bridge network, with UIs on
ports 8080 / 8081 / 8082 and optional external NAS shares for log storage.

## Quick start

```sh
scripts/yardctl prereqs    # fresh system: install container runtime
scripts/yardctl up         # build + start the suite
scripts/yardctl firewall   # open ports (firewalld/ufw, needs sudo)
scripts/yardctl status     # health check; also: down / restart / logs / smoke
```

UIs: hose http://localhost:8080 · valve http://localhost:8081 · bucket
http://localhost:8082. External syslog entry: host port **6514** (udp/tcp)
into the valve's IN port 514.

See [docs/PLAN.md](docs/PLAN.md) for the build plan. Status: S3 complete —
filter nodes (severity/program/regex with match/else ports) and cache nodes
(logrotate retention, external shares) work end-to-end; a FortiGate security
demo ships pre-wired (hose → valve splits critical/high to the bucket,
noise to disk). Next: S4 cross-UI cohesion.
