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
http://localhost:8082 — each UI carries a small **yard** nav linking to the
other two. External syslog entry: host port **6514** (udp/tcp) into the
valve's IN ports. Note: VM-based runtimes (Rancher/Docker Desktop, Colima)
forward TCP but not UDP across the VM boundary — `yardctl smoke` probes
both and tells you which arrived.

Log storage can target external NAS shares (NFS/CIFS) — see
[docs/SHARES.md](docs/SHARES.md).

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

## Status

See [docs/PLAN.md](docs/PLAN.md) for the build plan. S5 complete — ops
polish: TLS in/out on the valve (RFC 5425 listeners with one-click
self-signed certs, verified or lab-mode TLS forwarding), live tail of
every message entering the valve, config history with timestamped
previews before rollback, graph import/export, a GHCR publish workflow,
and rootless-podman quadlet units ([deploy/quadlet](deploy/quadlet)).
Next: S6 auth & collaboration.
