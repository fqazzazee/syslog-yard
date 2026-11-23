# syslog-yard

## Agent skills

### Issue tracker

Issues and specs live in this repo's GitHub Issues. Use the `gh` CLI. Report
security problems through private advisories, never in a public issue
(see `SECURITY.md`).

### Triage labels

The `triage` and `to-spec` skills use these label strings unchanged:
`needs-triage`, `needs-info`, `ready-for-agent`, `ready-for-human`, `wontfix`.
Only `wontfix` exists so far. Create the others with `gh label create` the
first time one is needed. Categories are the existing `bug` and `enhancement`
labels. External PRs are not a triage surface.

### Domain docs

Single context: `GLOSSARY.md` at the root and decisions in `docs/DECISIONS.md`.
Neither exists yet. The `domain-modeling` skill creates them when a term or
decision is settled.
