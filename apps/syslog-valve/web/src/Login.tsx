import { useState } from "react";
import { api, type AuthUser } from "./api";
import { Icon } from "./Icon";

// Login gates the UI when the deployment wires yard auth (YARD_AUTH_URL):
// credentials are the user accounts defined in syslog-bucket.
export function Login({ onLogin }: { onLogin: (u: AuthUser) => void }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const submit = (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError("");
    api
      .login(username, password)
      .then(onLogin)
      .catch((err: Error) => {
        setError(err.message);
        setBusy(false);
      });
  };

  return (
    <div className="login-wrap">
      <form className="login-card" onSubmit={submit}>
        <h1 className="brand">
          <span className="logo">
            <Icon name="valve" size={22} />
          </span>{" "}
          syslog-valve
        </h1>
        <p className="login-hint">Sign in with your yard account (managed in syslog-bucket).</p>
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
        {error && <div className="login-error">{error}</div>}
        <button className="primary" type="submit" disabled={busy || !username || !password}>
          <Icon name="login" size={16} /> Sign in
        </button>
      </form>
    </div>
  );
}
