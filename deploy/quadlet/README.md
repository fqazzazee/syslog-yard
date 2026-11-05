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

Check: `systemctl --user status 'syslog-*' 'bucket-*'` (or
`scripts/yardctl status`) and the UIs on 8080/8081/8082. On first start the
bucket generates a random `admin` password and logs it once — find it with
`journalctl --user -u syslog-bucket | grep -i password`, or set a fresh one
any time with `scripts/yardctl reset-admin` (it detects the quadlet
containers and uses `podman exec`; `yardctl smoke` works the same way).
`BUCKET_ADMIN_PASSWORD` in `syslog-bucket.container` is commented out on
purpose; uncomment it only to pin a known password for an automated
bootstrap (see [docs/AUTH.md](../../docs/AUTH.md)). The other `yardctl`
commands (`up`, `down`, `logs`, …) drive compose — use `systemctl --user`
and `journalctl --user` for the units. To start the yard at boot without
logging in:

```sh
loginctl enable-linger $USER
```

## Images

The units reference locally built images (`localhost/syslog-<tool>:latest`) —
no registry. Build them once from the repo root before starting the units:

```sh
# context is apps/ so each image can also copy apps/shared; --pull picks up
# patched base images on every rebuild
podman build --pull -t localhost/syslog-hose:latest -f apps/syslog-hose/Dockerfile apps
podman build --pull -t localhost/syslog-valve:latest -f apps/syslog-valve/Dockerfile apps
podman build --pull -t localhost/syslog-bucket:latest -f apps/syslog-bucket/Dockerfile apps
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

## Hardening defaults

- `bucket-db` sits on its own internal network (`bucket-db.network`) shared
  only with `syslog-bucket`.
- hose and bucket run as non-root with every capability dropped; the valve
  stays root inside its container (existing `valve-data` volumes are
  root-owned, and syslog-ng binds the ports you draw) but keeps only
  `NET_BIND_SERVICE`, `CHOWN`, `DAC_OVERRIDE` and `FOWNER`. All three set
  `NoNewPrivileges=true` and carry a `HealthCmd`; the bucket unit uses
  `Notify=healthy`, so `bucket-syslog` starts once the bucket answers.
- `syslog-bucket` gets a 30 s stop timeout (`PodmanArgs=--stop-timeout=30`)
  so a stop can drain its ingest queue and queued notifications.
- Logins through the hose and valve are proxied to the bucket.
  `syslog-bucket.container` trusts those two containers by name
  (`YARD_TRUSTED_PROXIES=syslog-hose,syslog-valve`), so the login throttle
  counts each browser separately. Don't replace the names with the `yard`
  subnet: a client reaching a published port can appear from that network
  and would then forge its address (see
  [docs/SECURITY.md](../../docs/SECURITY.md#client-addresses-behind-the-hose-valve-or-a-proxy)).
- To publish the UIs on loopback only (single-host lab), prefix each
  `PublishPort=` with `127.0.0.1:` — the quadlet equivalent of compose's
  `YARD_BIND`.
- Postgres password: the units keep the historical default
  (`syslog_bucket`) so existing volumes keep working. To change it, edit
  `POSTGRES_PASSWORD` in `bucket-db.container` (new volume) or run the
  `ALTER ROLE` from [docs/SECURITY.md](../../docs/SECURITY.md) (existing
  volume), and put the same value in `BUCKET_DB_URL` in
  `syslog-bucket.container`.

## Updating

Rebuild the image(s) from updated source, then restart:

```sh
podman build --pull -t localhost/syslog-hose:latest -f apps/syslog-hose/Dockerfile apps   # etc.
systemctl --user restart syslog-hose syslog-valve syslog-bucket bucket-syslog
```

Volumes (`hose-data`, `valve-data`, `bucket-dbdata`) survive restarts and
image updates; remove them with `podman volume rm` if you want a clean slate.
