import { useState, type FormEvent } from "react";
import { errorText } from "./http";
import { Icon } from "./Icon";
import { toolDef, type ToolId } from "./suite";
import { Banner, Button, Field } from "./ui";
import { authApi, type AuthUser } from "./yardAuthApi";

// Login is the sign-in screen of every yard tool. Accounts live in
// syslog-bucket (the identity provider); hose and valve proxy the login to
// it, and one sign-in covers all three tools on the same host. oidc adds the
// SSO button when the bucket has OIDC configured.
export function Login<U extends AuthUser = AuthUser>({
  tool,
  onLogin,
  oidc,
  notice,
}: {
  tool: ToolId;
  onLogin: (u: U) => void;
  oidc?: { name: string } | null;
  notice?: string; // e.g. "Your session ended — sign in again."
}) {
  const t = toolDef(tool);
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError("");
    try {
      onLogin((await authApi.login(username, password)) as U);
    } catch (err) {
      setError(errorText(err));
      setBusy(false);
    }
  };

  return (
    <main className="login-wrap">
      <form className="login-card" onSubmit={(e) => void submit(e)} aria-labelledby="login-title">
        <div className="login-brand">
          <Icon name="yard" size={26} />
          <span>syslog-yard</span>
        </div>
        <h1 id="login-title" className="login-title">
          <Icon name={t.icon} size={20} /> Sign in to {t.name}
        </h1>
        <p className="hint">
          {tool === "bucket"
            ? "One yard account covers hose, valve and bucket."
            : "Use your yard account (managed in syslog-bucket)."}
        </p>
        {notice && !error && <Banner kind="info">{notice}</Banner>}
        <Field label="Username">
          <input value={username} onChange={(e) => setUsername(e.target.value)} autoFocus autoComplete="username" />
        </Field>
        <Field label="Password">
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            autoComplete="current-password"
          />
        </Field>
        {error && <Banner kind="error">{error}</Banner>}
        <Button variant="primary" type="submit" icon="login" className="login-submit" disabled={busy || !username || !password}>
          {busy ? "Signing in…" : "Sign in"}
        </Button>
        {oidc && (
          <a className="oidc-btn" href="/api/auth/oidc/login">
            Sign in with {oidc.name || "SSO"}
          </a>
        )}
      </form>
    </main>
  );
}
