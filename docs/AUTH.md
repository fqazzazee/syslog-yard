# Authentication & collaboration (syslog-bucket)

syslog-bucket is the multi-user tool in the yard: it holds your team's
triage state, so its UI and API sit behind sign-in. syslog-hose and
syslog-valve are single-operator admin tools — they ship without built-in
auth; put them behind your reverse proxy's auth (or keep their ports
internal) when exposing the yard beyond a lab.

## First sign-in

On first start with an empty database the bucket creates an `admin`
account:

- `BUCKET_ADMIN_PASSWORD` set → that's the password
  (`deploy/compose.yaml` ships `yardadmin`; change it after first login
  via **👤 → Account…**).
- unset → a random password is generated and printed once in the
  container log (`docker compose logs syslog-bucket | grep admin`).

## Roles

| Role | Can |
|---------|-----------------------------------------------------------------|
| admin | everything: manage users, see/edit/delete every bucket |
| analyst | full triage: entries, tags, rules; create and share own buckets |
| viewer | read-only: browse entries and visible buckets, live tail |

Admins manage accounts under **👤 → Users…**: add local users, change
roles, reset passwords, disable (revokes all sessions immediately), or
delete. You cannot demote, disable, or delete your own account.

## Bucket sharing

Buckets (saved searches) are personal by default:

- A bucket you create is **yours** — others don't see it.
- Share it from the bucket's edit dialog: pick users, each as view-only
  or **can edit**. Editing covers name/description/condition; deleting and
  re-sharing stay with the owner (and admins).
- Buckets that existed before S6, or whose owner was deleted, are
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

The login page gains a "Sign in with …" button. First sign-in
auto-provisions an account bound to the OIDC subject (username from
`preferred_username`/`email`); admins can adjust its role afterwards like
any other account. OIDC accounts have no local password — password
management stays at the IdP.

## Sessions & deployment notes

- Sessions are opaque cookies (`HttpOnly`, `SameSite=Lax`), valid 30 days;
  only a SHA-256 of the token is stored server-side. Password changes and
  account disables revoke existing sessions.
- Serving over HTTPS (recommended outside a lab)? Set
  `BUCKET_COOKIE_SECURE=true` so cookies are marked `Secure`.
- The ingest path (syslog-ng → `BUCKET_INGEST_ADDR`) is not behind auth —
  it's an internal listener on the compose network. Don't publish it.
- `GET /api/healthz` and `GET /api/hints` stay unauthenticated (liveness
  probes, cross-tool nav); everything else under `/api/` requires a
  session.
