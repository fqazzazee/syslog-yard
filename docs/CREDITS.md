# Open-source credits

[syslog-yard](../README.md) stands on a small, deliberate set of open-source
projects and public data services. This page lists everything the suite builds
on, what each piece does here, and its license. Thank you to all of the
maintainers.

## Languages & frameworks

| | Project | License | Used for |
|---|---|---|---|
| ![Go](https://img.shields.io/badge/Go-00ADD8?logo=go&logoColor=white) | [Go](https://go.dev) | BSD-3-Clause | All three backends (hose, valve, bucket) |
| ![TypeScript](https://img.shields.io/badge/TypeScript-3178C6?logo=typescript&logoColor=white) | [TypeScript](https://www.typescriptlang.org) | Apache-2.0 | All three web UIs |
| ![React](https://img.shields.io/badge/React-20232a?logo=react&logoColor=61DAFB) | [React](https://react.dev) | MIT | UI framework for the three SPAs |
| ![Vite](https://img.shields.io/badge/Vite-646CFF?logo=vite&logoColor=white) | [Vite](https://vite.dev) | MIT | Frontend build tool (`@vitejs/plugin-react`) |
| ![Node.js](https://img.shields.io/badge/Node.js-5FA04E?logo=nodedotjs&logoColor=white) | [Node.js](https://nodejs.org) | MIT-style | Build-time only (UI compilation in Docker stage 1) |

## Engines & infrastructure

| | Project | License | Used for |
|---|---|---|---|
| ![syslog-ng](https://img.shields.io/badge/syslog--ng-0079c1) | [syslog-ng](https://github.com/syslog-ng/syslog-ng) | GPL-2.0 / LGPL-2.1 | The valve's data plane (the graph compiles to its config) and the bucket's ingest front |
| ![PostgreSQL](https://img.shields.io/badge/PostgreSQL-4169E1?logo=postgresql&logoColor=white) | [PostgreSQL](https://www.postgresql.org) 17 | PostgreSQL License | The bucket's entry store |
| ![logrotate](https://img.shields.io/badge/logrotate-555555) | [logrotate](https://github.com/logrotate/logrotate) | GPL-2.0 | Retention for the valve's disk-cache nodes |
| ![Alpine](https://img.shields.io/badge/Alpine_Linux-0D597F?logo=alpinelinux&logoColor=white) | [Alpine Linux](https://alpinelinux.org) | MIT (distro) | Runtime base for the valve and bucket images |
| ![Distroless](https://img.shields.io/badge/Distroless-4285F4) | [GoogleContainerTools distroless](https://github.com/GoogleContainerTools/distroless) | Apache-2.0 | Runtime base for the hose image |
| ![Docker](https://img.shields.io/badge/Docker-2496ED?logo=docker&logoColor=white) ![Podman](https://img.shields.io/badge/Podman-892CA0?logo=podman&logoColor=white) | [Docker](https://www.docker.com) / [Podman](https://podman.io) | Apache-2.0 | Container runtime + compose deployment (quadlets for podman) |

## Go libraries

The valve's backend is Go standard library only. Direct dependencies elsewhere:

| | Project | License | Used for |
|---|---|---|---|
| ![pgx](https://img.shields.io/badge/jackc%2Fpgx-4169E1?logo=postgresql&logoColor=white) | [jackc/pgx](https://github.com/jackc/pgx) | MIT | Bucket ↔ PostgreSQL driver & pool |
| ![websocket](https://img.shields.io/badge/coder%2Fwebsocket-555555) | [coder/websocket](https://github.com/coder/websocket) | ISC | The bucket's live-tail WebSocket |
| ![go-oidc](https://img.shields.io/badge/coreos%2Fgo--oidc-EE0000) | [coreos/go-oidc](https://github.com/coreos/go-oidc) | Apache-2.0 | OIDC single sign-on (with `golang.org/x/oauth2`) |
| ![x/crypto](https://img.shields.io/badge/golang.org%2Fx-00ADD8?logo=go&logoColor=white) | [golang.org/x/crypto](https://pkg.go.dev/golang.org/x/crypto), [x/oauth2](https://pkg.go.dev/golang.org/x/oauth2) | BSD-3-Clause | bcrypt password hashing; OAuth2 plumbing |
| ![yaml](https://img.shields.io/badge/gopkg.in%2Fyaml.v3-cb171e) | [go-yaml/yaml](https://github.com/go-yaml/yaml) | MIT / Apache-2.0 | The hose's preset file format |

(Indirect modules — `go-jose`, `pgpassfile`, `pgservicefile`, `puddle`,
`x/sync`, `x/text` — come with the above; see each app's `go.mod`.)

## Frontend libraries

| | Project | License | Used for |
|---|---|---|---|
| ![React Flow](https://img.shields.io/badge/React_Flow-FF0072) | [@xyflow/react (React Flow)](https://reactflow.dev) | MIT | The valve's node-graph canvas |
| ![Material Symbols](https://img.shields.io/badge/Material_Symbols-4285F4?logo=googlefonts&logoColor=white) | [Material Symbols](https://fonts.google.com/icons) (via [marella/material-symbols](https://github.com/marella/material-symbols)) | Apache-2.0 | All UI icons — self-hosted as inline SVG paths, no CDN |

## Online data sources

The bucket's network security view matches addresses against these public
databases (fetched periodically, cached locally; each has its own terms):

| | Source | Terms | Used for |
|---|---|---|---|
| ![Spamhaus](https://img.shields.io/badge/Spamhaus-DROP-8B0000) | [Spamhaus DROP](https://www.spamhaus.org/blocklists/do-not-route-or-peer/) | Free for non-commercial use | Known-malicious / hijacked netblocks |
| ![abuse.ch](https://img.shields.io/badge/abuse.ch-Feodo_Tracker-d32f2f) | [Feodo Tracker](https://feodotracker.abuse.ch) | CC0 | Botnet C2 addresses |
| ![Tor](https://img.shields.io/badge/Tor_Project-7D4698?logo=torproject&logoColor=white) | [Tor bulk exit list](https://check.torproject.org/torbulkexitlist) | Free | Tor exit-node addresses |
| ![Microsoft 365](https://img.shields.io/badge/Microsoft_365-0078D4) | [Microsoft 365 endpoints](https://learn.microsoft.com/en-us/microsoft-365/enterprise/microsoft-365-ip-web-service) | Public web service | Microsoft service ranges |
| ![MITRE](https://img.shields.io/badge/MITRE-ATT%26CK®-B22222) | [MITRE ATT&CK®](https://attack.mitre.org) | [Terms of use](https://attack.mitre.org/resources/legal-and-branding/terms-of-use/) | Technique/tactic names & IDs in the curated detection catalogs |

ATT&CK® is a registered trademark of The MITRE Corporation; alert-type names
in the OT view follow Claroty's public alert taxonomy. Neither vendor is
affiliated with or endorses this project.

## License compatibility

syslog-yard itself is [MIT](../LICENSE). GPL components (syslog-ng,
logrotate) run as separate processes/containers invoked over their normal
interfaces — their sources are unmodified and available upstream. The badge
images on this page are rendered by [shields.io](https://shields.io)
(CC0 service) when viewed on GitHub; nothing in the shipped containers loads
them.
