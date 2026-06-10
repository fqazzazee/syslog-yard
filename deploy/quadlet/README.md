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
8080/8081/8082. To start the yard at boot without logging in:

```sh
loginctl enable-linger $USER
```

## Images

Units reference `ghcr.io/syslog-yard/<tool>:latest`. To run locally built
images instead, build and retag, then change `Image=` (or add a
`.container.d` drop-in):

```sh
podman build -t ghcr.io/syslog-yard/syslog-hose:latest apps/syslog-hose
podman build -t ghcr.io/syslog-yard/syslog-valve:latest apps/syslog-valve
podman build -t ghcr.io/syslog-yard/syslog-bucket:latest apps/syslog-bucket
```

## Notes for real syslog sources

- Rootless podman cannot bind host ports <1024 by default; the valve's
  syslog entry is published as **6514 → 514** (udp+tcp), same as compose.
  To use 514 itself: `sudo sysctl net.ipv4.ip_unprivileged_port_start=514`.
- **Source IPs**: with slirp4netns every connection appears to come from the
  bridge gateway. Use pasta (default since podman 5) or, for a real edge box,
  host networking: in `syslog-valve.container` replace the `Network=` and
  `PublishPort=` lines with `Network=host` (then the valve reaches
  bucket-syslog via a published loopback port — see
  `deploy/compose.host-net.yaml` for the same pattern under compose).
- SELinux hosts: bind mounts in these units carry `:z`; keep it if you edit.

## Updating

```sh
podman pull ghcr.io/syslog-yard/syslog-hose:latest   # etc.
systemctl --user restart syslog-hose syslog-valve syslog-bucket bucket-syslog
```

Volumes (`hose-data`, `valve-data`, `bucket-dbdata`) survive restarts and
image updates; remove them with `podman volume rm` if you want a clean slate.
