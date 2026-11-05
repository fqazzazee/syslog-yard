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

- **unset (the shipped default)** → a random 128-bit password (32 hex
  characters) is generated and printed once in the log. Retrieve it with
  `scripts/yardctl logs syslog-bucket | grep -i password` (or
  `docker compose logs syslog-bucket | grep -i password`).
- `BUCKET_ADMIN_PASSWORD` set → that password is used instead. Useful for
  an automated/known bootstrap; change it after first login from the
  account menu (your name at the right of the top bar) → **Account…**.

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

Every yard UI carries the same **account menu** at the right of the top bar,
showing your name and a role badge: password change under **Account…**,
**Sign out**, and for admins **Users…** — add local users, change roles,
reset passwords, disable, or delete. Disabling an account, lowering its
role, and resetting its password all revoke its sessions immediately;
promotions keep them. On the hose and valve these actions are proxied to the bucket, which
enforces the roles. You cannot demote, disable, or delete your own
account. In the bucket, admins also get **Settings…** in this menu (single
sign-on and the session timeout, below).

## Bucket sharing

Buckets (saved searches) are personal by default:

- A bucket you create is **yours** — others don't see it.
- Share it from the bucket's edit dialog: pick users, each as view-only
  or **can edit**. Editing covers name/description/condition; deleting and
  re-sharing stay with the owner (and admins).
- Buckets created before ownership existed, or whose owner was deleted, are
  **yard buckets** (no owner): everyone sees them, analysts and admins may
  edit them.
- Shared-by/shared-with markers show in the bucket's side nav (a `· owner`
  suffix on someone else's bucket, a share icon on buckets you've shared) and
  on the **Buckets** page (`#/buckets`: an Owner column and a `shared`
  badge).

Tags and rules remain yard-wide: every analyst can manage them, viewers
see their effects.

## OIDC single sign-on

Any standard OIDC provider works (Keycloak, Authentik, Entra ID, Google,
…). Register a confidential client whose redirect URI is
`<bucket-url>/api/auth/oidc/callback`.

You can configure it two ways:

- **In the UI (recommended):** sign in to the bucket as an admin and open the
  account menu → **Settings… → Single sign-on (OIDC)**. Fill in the issuer, client id/secret,
  redirect URL, button label, and default role, then Save. It takes effect
  immediately, no restart: the login page's "Sign in with …" button appears (or
  disappears) right away. The client secret is stored but never sent back to the
  browser, so leaving the secret field blank on a later save keeps the existing
  one — as long as the issuer stays the same. Change the issuer and the stored
  secret is discarded (it would otherwise be sent to the new issuer's token
  endpoint): saving an enabled config with a new issuer and a blank secret
  answers 400 and asks you to re-enter it. On save the bucket probes the issuer's discovery document and warns (non
  fatally) if it can't be reached yet.
- **By environment variable** (legacy / infrastructure-as-code): set the vars
  below. They seed the config when nothing has been saved in the UI; once you
  save in the UI, the stored config takes over (it wins over the env vars).

| Env | Meaning |
|------------------------------|--------------------------------------------|
| `BUCKET_OIDC_ISSUER` | issuer URL (discovery is fetched from it) |
| `BUCKET_OIDC_CLIENT_ID` | client id |
| `BUCKET_OIDC_CLIENT_SECRET` | client secret |
| `BUCKET_OIDC_REDIRECT_URL` | the externally visible callback URL |
| `BUCKET_OIDC_NAME` | login-button label (default `SSO`) |
| `BUCKET_OIDC_DEFAULT_ROLE` | role for first-time OIDC users (default `viewer`) |

The settings live in the bucket's `app_settings` table, so they survive
restarts and are shared by every bucket replica pointed at the same database.

The bucket's login page gains a "Sign in with …" button. The sign-in uses
the authorization-code flow with `state`, PKCE (`S256`) and an ID-token
`nonce`, so the provider must accept PKCE (every current one does). If the
callback fails for any reason, the browser gets a generic "Single sign-on
failed" page and the reason goes to the bucket's log (`oidc sign-in failed`,
with the step). First sign-in auto-provisions an account bound to the OIDC subject (username from
`preferred_username`/`email`); admins can adjust its role afterwards like
any other account. New SSO users start as `viewer` (read-only) unless you
pick another default role. OIDC accounts have no local password — password
management stays at the IdP. OIDC users sign in **at the bucket**; on a
same-host deployment the resulting session covers the hose and valve too
(their own login forms take local credentials only).

### Walkthrough: SSO with authentik

A concrete end-to-end example. Replace `https://authentik.example.com` with
your authentik URL and `https://bucket.example.com` with the externally visible
bucket URL (for a local lab, `http://localhost:8082`).

**1. Create the provider in authentik.** Admin interface →
**Applications → Providers → Create → OAuth2/OpenID Provider**:

- **Name:** `syslog-bucket`
- **Authorization flow:** `default-provider-authorization-explicit-consent`
  (or the implicit-consent flow if you don't want a consent screen)
- **Client type:** `Confidential`
- **Client ID / Client Secret:** authentik generates these; copy both for step 3
- **Redirect URIs/Origins** (Strict): `https://bucket.example.com/api/auth/oidc/callback`
  (it must match the redirect URL you give the bucket exactly)
- **Signing Key:** the authentik self-signed key (the default)
- Leave the default scopes (`openid`, `profile`, `email`); the bucket reads
  `preferred_username`, `email`, and `name` from them.

**2. Create the application.** **Applications → Applications → Create**: name it
`syslog-bucket`, set the slug to `syslog-bucket`, and pick the provider from
step 1. Bind the users or groups who should get access under the application's
bindings.

**3. Note the issuer URL.** authentik issues per-application, so the issuer is:

```
https://authentik.example.com/application/o/syslog-bucket/
```

(the trailing slash matters; the provider page lists it, and discovery lives at
`<issuer>.well-known/openid-configuration`).

**4. Configure the bucket.** Sign in to the bucket as an admin, then account
menu → **Settings… → Single sign-on (OIDC)**:

| Field | Value |
|-------|-------|
| Enable OIDC | on |
| Issuer URL | `https://authentik.example.com/application/o/syslog-bucket/` |
| Client ID | from step 1 |
| Client secret | from step 1 |
| Redirect URL | `https://bucket.example.com/api/auth/oidc/callback` |
| Button label | `authentik` |
| Default role | `viewer` (the default; promote people explicitly afterwards) |

Save. The bucket probes discovery and warns if the issuer isn't reachable; a
clean save means it resolved.

**5. Sign in.** Sign out, then click **Sign in with authentik** on the login
page. First sign-in creates the local account (role = the default above);
an existing admin can change its role under **Users…** in the account menu.

**Gotchas.**

- The redirect URL must match the provider's registered URI character-for-
  character (authentik's Strict mode), including scheme, host, port, and path.
- Serving over HTTPS? Set `BUCKET_COOKIE_SECURE=true` on the bucket (and
  `YARD_COOKIE_SECURE=true` on hose/valve) so the session cookie is `Secure`.
- If you run the bucket behind a reverse proxy, the redirect URL is the public
  URL the browser sees, not the internal container address.

## Sessions & deployment notes

- Sessions are opaque cookies (`HttpOnly`, `SameSite=Lax`); only a SHA-256 of
  the token is stored server-side. Changing your own password signs out your
  other sessions; an admin disabling, demoting, or resetting the password of
  an account signs out all of its sessions. The hose/valve verification cache
  means revocation reaches them within ~30 seconds, and an open live tail in
  the bucket re-checks its session every 30 seconds and closes once it's
  gone.
- **Idle timeout (login timeout).** A session expires after a configurable
  period of inactivity (default 30 days). Admins set it in the bucket under account
  menu → **Settings… → Session**. Any authenticated request slides the expiry forward, so the timeout
  effectively starts once a browser tab is closed or left idle. Note that an open
  tab polling the UI counts as activity. The expiry is throttled to at most one
  write per minute per session, so it adds no meaningful load. Lowering the
  timeout also shortens sessions that are already open; raising it doesn't
  extend them.
- **Failed sign-ins are throttled.** Ten wrong passwords for one username
  from one client address lock that pair out for 5 minutes (the count keeps
  growing while failures arrive less than 5 minutes apart); 100 failures for
  one username from all addresses within 15 minutes lock the account for 15
  minutes. Password changes are throttled the same way, per user. Unknown
  usernames cost the same bcrypt comparison as real ones and get the same
  answer. Logins made through the hose or valve arrive from those
  containers, so unless the bucket trusts them as proxies, all of them share
  one per-address budget per tool — see
  [SECURITY.md](SECURITY.md#client-addresses-behind-the-hose-valve-or-a-proxy)
  for `YARD_TRUSTED_PROXIES`.
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
- State-changing requests (POST/PUT/PATCH/DELETE) must come from the UI's
  own origin: every tool rejects cross-site/same-site fetch metadata and a
  mismatched `Origin`, and the bucket additionally requires POSTs to its API
  to be `application/json` (415 otherwise; logout is exempt). Behind a
  reverse proxy that rewrites `Host`, set
  `YARD_TRUSTED_ORIGINS=https://yard.example.com` (or
  `YARD_TRUSTED_PROXIES=<proxy IP/CIDR>` to honour its `X-Forwarded-Host`)
  on each tool, and `BUCKET_WS_ORIGINS` on the bucket for live tail. See
  [SECURITY.md](SECURITY.md).
