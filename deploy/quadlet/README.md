# Running the yard under rootless podman (quadlet)

These units run the whole suite as **user** systemd services — no root, no
compose. Requires podman ≥ 4.6 (Notify=healthy needs 4.6; Fedora and recent
Debian/Ubuntu qualify).

## Install

```sh
mkdir -p ~/.config/containers/systemd ~/.config/syslog-yard
cp deploy/quadlet/* ~/.config/containers/systemd/
cp deploy/syslog-ng/bucket.conf ~/.config/syslog-yard/bucket.conf
systemctl --user daemon-reload
systemctl --user start syslog-hose syslog-valve bucket-syslog
```

`bucket-syslog` pulls in `syslog-bucket` and `bucket-db` via dependencies;
the db unit only reports started once Postgres answers `pg_isready`.

Check: `systemctl --user status 'syslog-*' 'bucket-*'` and the UIs on
8080/8081/8082. The bucket's initial admin password comes from
`BUCKET_ADMIN_PASSWORD` in `syslog-bucket.container` (see
[docs/AUTH.md](../../docs/AUTH.md)). To start the yard at boot without
logging in:

```sh
loginctl enable-linger $USER
```

## Images

The units reference locally built images (`localhost/syslog-<tool>:latest`) —
no registry. Build them once from the repo root before starting the units:

```sh
podman build -t localhost/syslog-hose:latest apps/syslog-hose
podman build -t localhost/syslog-valve:latest apps/syslog-valve
podman build -t localhost/syslog-bucket:latest apps/syslog-bucket
```

(`scripts/yardctl up` builds the same images under compose; the quadlet units
reuse them.)

## Notes for real syslog sources

- Rootless podman cannot bind host ports <1024 by default; the valve's
  syslog entry is published as **6514 → 6514** (udp+tcp), landing on the
  valve's External IN block — same as compose. To use 514 itself:
  `sudo sysctl net.ipv4.ip_unprivileged_port_start=514`.
- **Source IPs**: with slirp4netns every connection appears to come from the
  bridge gateway. Use pasta (default since podman 5) or, for a real edge box,
  host networking: in `syslog-valve.container` replace the `Network=` and
  `PublishPort=` lines with `Network=host` (then the valve reaches
  bucket-syslog via a published loopback port — see
  `deploy/compose.host-net.yaml` for the same pattern under compose).
- SELinux hosts: bind mounts in these units carry `:z`; keep it if you edit.

## Updating

Rebuild the image(s) from updated source, then restart:

```sh
podman build -t localhost/syslog-hose:latest apps/syslog-hose   # etc.
systemctl --user restart syslog-hose syslog-valve syslog-bucket bucket-syslog
```

Volumes (`hose-data`, `valve-data`, `bucket-dbdata`) survive restarts and
image updates; remove them with `podman volume rm` if you want a clean slate.
