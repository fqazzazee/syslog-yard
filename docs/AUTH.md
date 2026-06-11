# Authentication & collaboration

**syslog-bucket is the yard's identity provider.** Users, passwords, roles,
and OIDC all live there; syslog-hose and syslog-valve don't store any
accounts. When a deployment sets `YARD_AUTH_URL` on the hose or valve
(the shipped compose and quadlet files do), that tool's UI and API are
guarded by the same accounts: login is proxied to the bucket, and every
request's session is verified against it (cached ~30 s).

**One sign-in covers the whole yard** on a standard deployment: the
session cookie is host-scoped (ports don't matter), so signing in at any
of the three UIs on `localhost:8080/8081/8082` signs you into all of
them, and signing out anywhere revokes the session everywhere.

Removing `YARD_AUTH_URL` returns a tool to its open, standalone behavior —
appropriate for a lab or when you front it with reverse-proxy auth instead.

## First sign-in

On first start with an empty database the bucket creates an `admin`
account:

- **unset (the shipped default)** → a strong random password is generated
  and printed once in the log. Retrieve it with
  `scripts/yardctl logs syslog-bucket | grep -i password` (or
  `docker compose logs syslog-bucket | grep -i password`).
- `BUCKET_ADMIN_PASSWORD` set → that password is used instead. Useful for
  an automated/known bootstrap; change it after first login via
  **👤 → Account…**.

Forgot it, or want to rotate the generated one? `scripts/yardctl
reset-admin` sets a fresh random password (and prints it), re-enables the
account, and signs out other admin sessions. Without the script, the same
thing runs as `docker compose exec syslog-bucket syslog-bucket
reset-admin` (append a password to set a known one).

## Roles

| Role | In the bucket | In the hose & valve |
|---------|-----------------------------------------------------------------|------------------------------|
| admin | everything: manage users, see/edit/delete every bucket | full control |
| analyst | full triage: entries, tags, rules; create and share own buckets | full control |
| viewer | read-only: browse entries and visible buckets, live tail | read-only: watch jobs, graph, live tail |

Every yard UI carries the same **👤 account menu**: password change under
**Account…**, and for admins **Users…** — add local users, change roles,
reset passwords, disable (revokes all sessions immediately), or delete.
On the hose and valve these actions are proxied to the bucket, which
enforces the roles. You cannot demote, disable, or delete your own
account.

## Bucket sharing

Buckets (saved searches) are personal by default:

- A bucket you create is **yours** — others don't see it.
- Share it from the bucket's edit dialog: pick users, each as view-only
  or **can edit**. Editing covers name/description/condition; deleting and
  re-sharing stay with the owner (and admins).
- Buckets created before ownership existed, or whose owner was deleted, are
  **yard buckets** (no owner): everyone sees them, analysts and admins may
  edit them.
- Shared-by/shared-with markers show in the sidebar (`· owner` suffix,
  `⇄` on buckets you've shared).

Tags and rules remain yard-wide: every analyst can manage them, viewers
see their effects.

## OIDC single sign-on

Any standard OIDC provider works (Keycloak, Authentik, Entra ID, Google,
…). Register a confidential client whose redirect URI is
`<bucket-url>/api/auth/oidc/callback`, then set:

| Env | Meaning |
|------------------------------|--------------------------------------------|
| `BUCKET_OIDC_ISSUER` | issuer URL (discovery is fetched from it) |
| `BUCKET_OIDC_CLIENT_ID` | client id |
| `BUCKET_OIDC_CLIENT_SECRET` | client secret |
| `BUCKET_OIDC_REDIRECT_URL` | the externally visible callback URL |
| `BUCKET_OIDC_NAME` | login-button label (default `SSO`) |
| `BUCKET_OIDC_DEFAULT_ROLE` | role for first-time OIDC users (default `analyst`) |

The bucket's login page gains a "Sign in with …" button. First sign-in
auto-provisions an account bound to the OIDC subject (username from
`preferred_username`/`email`); admins can adjust its role afterwards like
any other account. OIDC accounts have no local password — password
management stays at the IdP. OIDC users sign in **at the bucket**; on a
same-host deployment the resulting session covers the hose and valve too
(their own login forms take local credentials only).

## Sessions & deployment notes

- Sessions are opaque cookies (`HttpOnly`, `SameSite=Lax`), valid 30 days;
  only a SHA-256 of the token is stored server-side. Password changes and
  account disables revoke existing sessions; the hose/valve verification
  cache means revocation reaches them within ~30 seconds.
- Serving over HTTPS (recommended outside a lab)? Set
  `BUCKET_COOKIE_SECURE=true` on the bucket and `YARD_COOKIE_SECURE=true`
  on the hose/valve so cookies are marked `Secure`.
- If the bucket is down, hose/valve logins and (uncached) API calls answer
  503 — the data planes (sending and routing syslog) keep running; only
  the UIs are affected.
- The ingest path (syslog-ng → `BUCKET_INGEST_ADDR`) is not behind auth —
  it's an internal listener on the compose network. Don't publish it. The
  same goes for the valve's syslog IN ports: auth covers UIs/APIs, not
  syslog traffic.
- `GET /api/healthz` and `GET /api/hints` stay unauthenticated (liveness
  probes, cross-tool nav); everything else under `/api/` requires a
  session, on every tool.
