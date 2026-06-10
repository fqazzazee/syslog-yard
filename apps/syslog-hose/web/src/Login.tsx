import { useState } from "react";
import { api, AuthUser } from "./api";

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
        <h1>
          <span className="logo">⟫⟫</span> syslog-hose
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
          Sign in
        </button>
      </form>
    </div>
  );
}
