# Contributing to syslog-yard

Thanks for wanting to help. syslog-yard is a small, opinionated project, and
contributions that respect that (focused changes, no drive-by rewrites) are
very welcome.

## Before you start

For anything bigger than a typo or an obvious bug fix, please open an issue
first and describe what you want to change and why. It saves you from building
something that doesn't fit the project's direction (see the README's
[mission](README.md#mission) and the "what it isn't" paragraph).

## Getting a dev environment

Everything builds from source; see the [README](README.md) for prerequisites.

```sh
git clone https://github.com/fqazzazee/syslog-yard
cd syslog-yard
scripts/yardctl up        # build + start the whole suite
scripts/yardctl smoke     # end-to-end check
```

For work on a single tool, each app is its own Go module with its own README
covering standalone use, env vars, and a UI dev server:

- [apps/syslog-hose](apps/syslog-hose/README.md)
- [apps/syslog-valve](apps/syslog-valve/README.md)
- [apps/syslog-bucket](apps/syslog-bucket/README.md)

Code every tool needs lives once in [apps/shared](apps/shared): the `yardauth`
guard, the hardening headers, the ATT&CK catalog, and the shared web UI in
`apps/shared/web/src`:

- styles: `tokens.css` (palette, spacing, type, the focus ring, and each
  tool's accent, in both themes), `components.css`, and `shell.css`;
- the frame: `AppShell` (top bar, tool switcher, side nav, skip link), with
  the tool and section map and the cross-tool link helpers in `suite.ts`;
- primitives: `ui.tsx` (`Button`, `IconButton`, `Field`, `Banner`,
  `EmptyState`, `Loading`, `Badge`, `PageHeader`, `Tabs`), `Dialog`, `Menu`,
  `Toast`, and `Icon`;
- shared screens: `Login`, `About`, and `AccountMenu` (password change and
  user management, backed by `yardAuthApi.ts`);
- helpers: `http.ts` (the JSON request helper, `ApiError`, and session-expiry
  handling), `hooks.ts` (`useVisibleInterval`, `useMediaQuery`,
  `useStoredState`, `useHashRoute`), and `theme.ts`.

Each app imports these directly by relative path, along with the three
stylesheets in its `main.tsx`. Only the bucket keeps local stand-ins:
`components/Icon.tsx` and the `useVisibleInterval` export in `hooks.ts`
re-export the shared code, and `components/Modal.tsx` wraps `Dialog`. Edit
the shared code, not those. Text and background pairs must stay WCAG AA
(4.5:1) in both themes, so check any new pair before adding it. The apps consume `apps/shared` via a
`replace` directive (Go) and relative imports (web), wired together by the
root `go.work`.

## Tests

CI runs `go test ./...` for each module on every push and pull request
([.github/workflows/test.yaml](.github/workflows/test.yaml)). Run the same
thing locally before opening a PR:

```sh
cd apps/syslog-bucket && go test ./...   # repeat for shared / syslog-hose / syslog-valve
```

Two kinds of test skip themselves when their dependency is missing (CI
included): the bucket's Postgres-backed tests need `BUCKET_TEST_DSN` (see
[apps/syslog-bucket](apps/syslog-bucket/README.md#tests)), and the valve's
integration tests need `syslog-ng` and `logrotate` on the `PATH`. If you touch
the bucket's store, ingest or search code, or the valve's config generator,
run them locally.

A PR needs all four modules green. If your change has a visible effect,
exercise it through the UI too (`scripts/yardctl up`), not just the tests.

## Style

- Go code is `gofmt`-formatted; follow the patterns already in the package
  you're touching.
- The valve's backend is deliberately **standard library only** — don't add a
  Go dependency to it without discussing in an issue first. New dependencies
  anywhere should pull real weight, and get a row in
  [docs/CREDITS.md](docs/CREDITS.md).
- UIs are TypeScript + React; icons are self-hosted Material Symbols (no CDN
  or external origins — the CSP in every app enforces `default-src 'self'`).
- If a change alters behavior described in the README or `docs/`, update the
  docs in the same PR.

## Commits and pull requests

- Keep PRs focused: one topic per PR.
- Write plain, descriptive commit messages (look at `git log` for the tone).
- Security-relevant changes should note their impact against the threat model
  in [docs/SECURITY.md](docs/SECURITY.md).

## Reporting security issues

Don't open a public issue. Report vulnerabilities privately as described in
the [security policy](SECURITY.md) (GitHub private vulnerability reporting is
enabled for this repository).

## License

syslog-yard is source-available under PolyForm Noncommercial or PolyForm
Internal Use, plus commercial licenses on request (see [LICENSE](LICENSE)). By
contributing, you license your work to Fadi Qazzazee under the MIT License. That
lets it ship under all of those licenses.
