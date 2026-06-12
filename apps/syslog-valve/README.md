# ⊶ syslog-valve

Visual router/filter for syslog, part of [syslog-yard](../../README.md).
syslog-ng is the data plane; syslog-valve is the control plane: you wire
graphical **IN ports** (listeners) to **OUT ports** (forward destinations) on a
canvas, hit **Apply**, and the app compiles the graph to syslog-ng config,
validates it with `--syntax-only`, swaps it atomically and reloads via SIGHUP.
Every applied version is kept for one-click rollback.

Beyond the spine: facility/severity/host/program/regex **filters** with
if/else routing, **drop** sinks, **cache** nodes writing to `/data` or an
external share with logrotate-compiled retention, **TLS** in and out
(one-click self-signed certs), **live tail** of everything entering the
valve, **live per-wire throughput** (msgs/sec read from `syslog-ng-ctl stats`
and rendered on the canvas edges), config **version history** with previews,
and graph import/export.

## Run (standalone)

```sh
make image
docker run -d --name syslog-valve -p 8081:8081 -p 5514:514/udp \
  -v valve-data:/data syslog-valve:latest
```

UI on http://localhost:8081. Listeners you define bind *inside* the
container — publish the matching ports (e.g. `-p 5514:514/udp` for an IN port
on 514/udp).

## Environment

| Variable                  | Default     | Purpose                          |
|---------------------------|-------------|----------------------------------|
| `VALVE_ADDR`              | `:8081`     | Web UI / API listen address      |
| `VALVE_DATA`              | `/data`     | Graph, configs, history          |
| `VALVE_SUGGESTED_FORWARD` | _(unset)_   | Pre-fills new OUT ports (host:port) |
| `VALVE_SYSLOGNG_BIN`      | `syslog-ng` | Data-plane binary                |
| `YARD_AUTH_URL`           | _(unset)_   | Guard the UI with syslog-bucket's accounts (unset = open) |
| `YARD_COOKIE_SECURE`      | `false`     | Mark session cookies `Secure` (HTTPS) |

## Development

```sh
make test       # Go unit tests (no syslog-ng needed)
make build      # UI + binary; needs node and go
cd web && npm run dev   # UI dev server proxying /api to :8081
```
