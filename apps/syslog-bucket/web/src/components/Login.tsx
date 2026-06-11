import { useState } from "react";
import { login } from "./../api";
import type { AuthInfo, User } from "./../types";
import { Icon } from "./Icon";

interface Props {
  info: AuthInfo | null;
  onLogin: (u: User) => void;
}

export default function Login({ info, onLogin }: Props) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      onLogin(await login(username, password));
    } catch (err) {
      setError(String(err instanceof Error ? err.message : err));
      setBusy(false);
    }
  };

  return (
    <div className="login-wrap">
      <form className="login-card" onSubmit={(e) => void submit(e)}>
        <h1 className="brand">
          <span className="logo">
            <Icon name="inbox" size={22} />
          </span>{" "}
          syslog-bucket
        </h1>
        <p className="hint">Sign in to triage the yard's logs.</p>
        <label>
          Username
          <input value={username} onChange={(e) => setUsername(e.target.value)} autoFocus autoComplete="username" />
        </label>
        <label>
          Password
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            autoComplete="current-password"
          />
        </label>
        {error && <div className="error">{error}</div>}
        <button className="primary" type="submit" disabled={busy || !username || !password}>
          <Icon name="login" size={16} /> Sign in
        </button>
        {info?.oidc.enabled && (
          <a className="oidc-btn" href="/api/auth/oidc/login">
            Sign in with {info.oidc.name || "SSO"}
          </a>
        )}
      </form>
    </div>
  );
}
