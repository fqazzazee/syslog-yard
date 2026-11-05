# ⊶ syslog-valve

Visual router/filter for syslog, part of [syslog-yard](../../README.md).
syslog-ng is the data plane; syslog-valve is the control plane: you wire
graphical **IN ports** (listeners) to **OUT ports** (forward destinations) on a
canvas, hit **Apply**, and the app compiles the graph to syslog-ng config,
validates it with `--syntax-only`, swaps it atomically, reloads via SIGHUP
and waits for syslog-ng to confirm. Every applied version is kept for
one-click rollback.

Beyond the spine: facility/severity/host/program/regex **filters** with
if/else routing, **drop** sinks, **cache** nodes writing to `/data` or an
external share with logrotate-compiled retention, **TLS** in and out
(one-click self-signed certs), **live tail** of everything entering the
valve, **live per-wire throughput** (msgs/sec read from `syslog-ng-ctl stats`
and rendered on the canvas edges), config **version history** with previews,
and graph import/export.

## Run (standalone)

```sh
make image   # builds with -f Dockerfile .. (context is apps/, for apps/shared)
docker run -d --name syslog-valve -p 8081:8081 -p 5514:514/udp \
  -v valve-data:/data syslog-valve:latest
```

UI on http://localhost:8081. Listeners you define bind *inside* the
container — publish the matching ports (e.g. `-p 5514:514/udp` for an IN port
on 514/udp).

## Web UI

The valve uses the suite's shared app shell (see
[Navigation and deep links](../../README.md#navigation-and-deep-links)). Its
side nav starts as an icon rail so the canvas keeps its room, and it has three
pages:

- **Flow** (`#/flow`): the canvas. The page header holds an **Add node** menu
  (Internal IN, External IN, Filter, OUT port, Cache, Notify), **Export**,
  **Import** and **Apply**, plus an *unsaved changes* badge while the canvas
  differs from the saved graph. Selecting a node opens its panel; below
  900 px the panel becomes a bottom sheet. A notify node's panel shows its
  sent / failed / dropped counts and the rate limit in effect. The live tail
  folds out from the footer.
- **History** (`#/history`): the applied configs as a table with **View**
  and **Roll back**, and the active syslog-ng config on a second tab.
- **Live tail** (`#/tail`): everything entering the valve, by IN port.

Apply and rollback results show as a banner at the top of the page: an error
when the valve refuses, or a warning when the config was installed but
syslog-ng didn't confirm it (for example, because it isn't running). When a
422 names nodes, the canvas outlines them, selects the first, and repeats the
error in its panel.

## Applying a graph

- **Apply confirms the reload.** After the syntax check and the swap, the
  valve sends SIGHUP and watches syslog-ng's log for its verdict (15 s
  timeout). If syslog-ng refuses the new config (say, a port it can't
  bind) or gives no verdict in time, the previous `current.conf` is put
  back and Apply answers **422** with the reason; the running flow is
  untouched. If syslog-ng isn't running at all, the config is installed and
  archived anyway (so a crash loop can be fixed by applying a good graph)
  and the response carries a `warning`.
- **Listener checks.** Enabled sources may not share a (protocol, port):
  `tls` counts as `tcp`, `udp+tcp` claims both, and an empty or wildcard
  bind (`0.0.0.0`, `::`) overlaps every address. A source also can't take
  the TCP port of the valve's own UI (`VALVE_ADDR`). Both are rejected with
  422 before anything reaches syslog-ng.
- **Rollback** takes the graph archived with a history entry through the
  same path as Apply: it regenerates the syslog-ng config, `logrotate.conf`
  and the notify targets from that graph and records the result as a new
  history entry. Graphs archived by older versions are sanitized on load
  (control characters become spaces).
- **Request limits:** graph saves are capped at 1 MiB and notify tests at
  64 KiB; larger bodies get **413**.
- **Notify nodes** default to 60 deliveries/min (0 or empty means the
  default; there's no unlimited setting), with a 32-message queue per node.
  Per-node counters are at `GET /api/notify/stats`. See
  [docs/NOTIFICATIONS.md](../../docs/NOTIFICATIONS.md).
- **After upgrading**, Apply the graph once: the valve restarts with the
  config it last applied, and only a fresh Apply regenerates it with the
  new version's validation and escaping
  ([docs/SECURITY.md](../../docs/SECURITY.md)).

## Environment

| Variable                  | Default     | Purpose                          |
|---------------------------|-------------|----------------------------------|
| `VALVE_ADDR`              | `:8081`     | Web UI / API listen address      |
| `VALVE_DATA`              | `/data`     | Graph, configs, history          |
| `VALVE_SUGGESTED_FORWARD` | _(unset)_   | Pre-fills new OUT ports (host:port) |
| `VALVE_SYSLOGNG_BIN`      | `syslog-ng` | Data-plane binary                |
| `YARD_AUTH_URL`           | _(unset)_   | Guard the UI with syslog-bucket's accounts (unset = open) |
| `YARD_COOKIE_SECURE`      | `false`     | Mark session cookies `Secure` (HTTPS) |
| `YARD_SHARES`             | _(unset)_   | Comma-separated share names mounted at `/shares/<name>`, offered as cache locations ([docs/SHARES.md](../../docs/SHARES.md)) |
| `YARD_TRUSTED_ORIGINS`    | _(unset)_   | Extra Origins accepted on state-changing requests, for a reverse proxy that rewrites `Host` |
| `YARD_TRUSTED_PROXIES`    | _(unset)_   | IPs/CIDRs of a reverse proxy in front of the valve: its `X-Forwarded-Host` and `X-Forwarded-For` are believed ([docs/SECURITY.md](../../docs/SECURITY.md)) |
| `YARD_LINK_HOSE` / `_VALVE` / `_BUCKET` | _(unset)_ | Cross-tool nav links: a full URL, or a bare port resolved against the host the browser used |

## Development

```sh
make test       # Go tests; the syslog-ng/logrotate integration tests skip
                # unless those binaries are installed
make build      # UI + binary; needs node and go
cd web && npm run dev   # UI dev server proxying /api to :8081
```

## License

PolyForm Noncommercial or PolyForm Internal Use, with commercial licenses on
request — see [LICENSE](../../LICENSE) at the repo root. Third-party projects the
suite builds on are credited in [docs/CREDITS.md](../../docs/CREDITS.md).
