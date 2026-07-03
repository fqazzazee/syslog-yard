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

## Tests

CI runs `go test ./...` for each module on every push and pull request
([.github/workflows/test.yaml](.github/workflows/test.yaml)). Run the same
thing locally before opening a PR:

```sh
cd apps/syslog-bucket && go test ./...   # repeat for syslog-hose / syslog-valve
```

A PR needs all three modules green. If your change has a visible effect,
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

See the [Reporting section of docs/SECURITY.md](docs/SECURITY.md#reporting).

## License

syslog-yard is [MIT](LICENSE); by contributing you agree your work is
licensed the same way.
