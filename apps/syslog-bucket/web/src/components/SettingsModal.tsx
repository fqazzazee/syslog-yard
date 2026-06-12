import { useEffect, useState } from "react";
import { fetchSettings, saveOIDCSettings, saveSessionSettings } from "./../api";
import type { Settings } from "./../types";
import Modal from "./Modal";

interface Props {
  onClose: (changed: boolean) => void;
}

// Friendly rendering of an idle-timeout in minutes.
function humanMinutes(m: number): string {
  if (m % (60 * 24) === 0) return `${m / (60 * 24)} day${m / (60 * 24) === 1 ? "" : "s"}`;
  if (m % 60 === 0) return `${m / 60} hour${m / 60 === 1 ? "" : "s"}`;
  return `${m} min`;
}

export default function SettingsModal({ onClose }: Props) {
  const [s, setS] = useState<Settings | null>(null);
  const [secret, setSecret] = useState(""); // typed only when changing it
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    fetchSettings()
      .then(setS)
      .catch((e) => setError(String(e)));
  }, []);

  const patchOIDC = (p: Partial<Settings["oidc"]>) => s && setS({ ...s, oidc: { ...s.oidc, ...p } });

  const save = async () => {
    if (!s) return;
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      const res = await saveOIDCSettings({
        enabled: s.oidc.enabled,
        issuer: s.oidc.issuer.trim(),
        client_id: s.oidc.client_id.trim(),
        redirect_url: s.oidc.redirect_url.trim(),
        name: s.oidc.name.trim(),
        default_role: s.oidc.default_role,
        ...(secret ? { client_secret: secret } : {}),
      });
      await saveSessionSettings(s.session.idle_minutes);
      onClose(true);
      if (res.warning) alert(res.warning);
    } catch (e) {
      setError(String(e instanceof Error ? e.message : e));
      setBusy(false);
    }
  };

  return (
    <Modal title="Settings" onClose={() => onClose(false)}>
      {!s ? (
        <p className="hint">Loading…</p>
      ) : (
        <>
          <h3>Single sign-on (OIDC)</h3>
          <p className="hint">
            Sign users in through an identity provider (Keycloak, Authentik, Entra ID, Google, …).
            {s.oidc.source === "env" && " Currently set from environment variables; saving here takes over."}
          </p>
          <label className="check">
            <input
              type="checkbox"
              checked={s.oidc.enabled}
              onChange={(e) => patchOIDC({ enabled: e.target.checked })}
            />
            Enable OIDC sign-in
          </label>
          <label>
            Issuer URL
            <input
              value={s.oidc.issuer}
              onChange={(e) => patchOIDC({ issuer: e.target.value })}
              placeholder="https://idp.example.com/realms/yard"
            />
          </label>
          <label>
            Client ID
            <input value={s.oidc.client_id} onChange={(e) => patchOIDC({ client_id: e.target.value })} placeholder="syslog-bucket" />
          </label>
          <label>
            Client secret
            <input
              type="password"
              value={secret}
              onChange={(e) => setSecret(e.target.value)}
              placeholder={s.oidc.has_secret ? "•••••••• (leave blank to keep current)" : "(none set)"}
              autoComplete="new-password"
            />
          </label>
          <label>
            Redirect URL
            <input
              value={s.oidc.redirect_url}
              onChange={(e) => patchOIDC({ redirect_url: e.target.value })}
              placeholder={`${location.origin}/api/auth/oidc/callback`}
            />
          </label>
          <div className="cond-row">
            <label className="grow">
              Button label
              <input value={s.oidc.name} onChange={(e) => patchOIDC({ name: e.target.value })} placeholder="SSO" />
            </label>
            <label className="grow">
              Default role for new SSO users
              <select value={s.oidc.default_role} onChange={(e) => patchOIDC({ default_role: e.target.value as Settings["oidc"]["default_role"] })}>
                <option value="viewer">viewer</option>
                <option value="analyst">analyst</option>
                <option value="admin">admin</option>
              </select>
            </label>
          </div>

          <h3>Session</h3>
          <p className="hint">
            Sign-ins expire after this much inactivity. Any request from an open tab counts as activity, so the
            timeout applies once the UI is closed or idle. Currently {humanMinutes(s.session.idle_minutes)}.
          </p>
          <label>
            Idle timeout (minutes)
            <input
              type="number"
              min={1}
              max={525600}
              value={s.session.idle_minutes}
              onChange={(e) => setS({ ...s, session: { idle_minutes: Number(e.target.value) } })}
            />
          </label>

          {error && <div className="error">{error}</div>}
          {notice && <div className="notice">{notice}</div>}
          <div className="modal-foot">
            <button
              className="primary"
              disabled={busy || (s.oidc.enabled && !s.oidc.issuer.trim()) || s.session.idle_minutes < 1}
              onClick={() => void save()}
            >
              Save
            </button>
          </div>
        </>
      )}
    </Modal>
  );
}
