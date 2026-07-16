import { useEffect, useRef, useState } from "react";
import { authApi as api, type AuthUser, type YardUser } from "./yardAuthApi";
import { Icon } from "./Icon";

// AccountMenu is the yard-wide account dropdown: password change for
// everyone, user management for admins, sign out. Management calls are
// proxied to syslog-bucket (the identity provider), which enforces roles.
// One copy shared by syslog-hose and syslog-valve (their web/src copies are
// one-line shims). syslog-bucket renders the same button/dropdown markup
// inline in its App with its own richer UsersModal.

const ROLES = ["admin", "analyst", "viewer"] as const;

export function AccountMenu({ user, onSignOut }: { user: AuthUser; onSignOut: () => void }) {
  const [open, setOpen] = useState(false);
  const [modal, setModal] = useState<"none" | "users" | "account">("none");
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    const onDown = (e: MouseEvent) => {
      if (!ref.current?.contains(e.target as Node)) setOpen(false);
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setOpen(false);
    };
    document.addEventListener("mousedown", onDown);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onDown);
      document.removeEventListener("keydown", onKey);
    };
  }, [open]);

  return (
    <div className="user-menu" ref={ref}>
      <button className={`user-btn${open ? " open" : ""}`} title="Account menu" onClick={() => setOpen(!open)}>
        <Icon name="account_circle" size={16} /> {user.display_name || user.username}{" "}
        <span className={`role-badge role-${user.role}`}>{user.role}</span>
        <Icon name="keyboard_arrow_down" size={16} className="caret" />
      </button>
      {open && (
        <div className="user-dropdown" onClick={() => setOpen(false)}>
          {user.role === "admin" && (
            <button onClick={() => setModal("users")}>
              <Icon name="manage_accounts" size={16} /> Users…
            </button>
          )}
          <button onClick={() => setModal("account")}>
            <Icon name="account_circle" size={16} /> Account…
          </button>
          <button onClick={onSignOut}>
            <Icon name="logout" size={16} /> Sign out
          </button>
        </div>
      )}
      {modal === "account" && <AccountModal user={user} onClose={() => setModal("none")} />}
      {modal === "users" && <UsersModal me={user} onClose={() => setModal("none")} />}
    </div>
  );
}

function AccountModal({ user, onClose }: { user: AuthUser; onClose: () => void }) {
  const [oldPw, setOldPw] = useState("");
  const [newPw, setNewPw] = useState("");
  const [confirmPw, setConfirmPw] = useState("");
  const [error, setError] = useState("");
  const [done, setDone] = useState(false);

  const save = async () => {
    setError("");
    if (newPw !== confirmPw) {
      setError("New passwords do not match");
      return;
    }
    try {
      await api.changePassword(oldPw, newPw);
      setDone(true);
      setTimeout(onClose, 1200);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  };

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal acct-modal" onClick={(e) => e.stopPropagation()}>
        <div className="acct-head">
          <h2>Account — {user.username}</h2>
          <button className="acct-close" onClick={onClose}>
            <Icon name="close" size={18} />
          </button>
        </div>
        {user.has_password ? (
          <>
            <label>
              Current password
              <input type="password" value={oldPw} onChange={(e) => setOldPw(e.target.value)} autoFocus />
            </label>
            <label>
              New password (min 8 characters)
              <input type="password" value={newPw} onChange={(e) => setNewPw(e.target.value)} />
            </label>
            <label>
              Repeat new password
              <input type="password" value={confirmPw} onChange={(e) => setConfirmPw(e.target.value)} />
            </label>
            {error && <div className="form-error">{error}</div>}
            {done && <div className="form-notice">Password changed — other sessions were signed out.</div>}
            <div className="modal-actions">
              <button className="primary" disabled={!oldPw || newPw.length < 8 || done} onClick={() => void save()}>
                Change password
              </button>
            </div>
          </>
        ) : (
          <p className="acct-hint">This account signs in via OIDC; manage its password at your identity provider.</p>
        )}
      </div>
    </div>
  );
}

function UsersModal({ me, onClose }: { me: AuthUser; onClose: () => void }) {
  const [users, setUsers] = useState<YardUser[]>([]);
  const [error, setError] = useState("");
  const [newUser, setNewUser] = useState({ username: "", password: "", role: "analyst" as string });

  const reload = () => api.users().then(setUsers).catch((e: Error) => setError(e.message));
  useEffect(() => {
    void reload();
  }, []);

  const run = async (op: () => Promise<unknown>) => {
    setError("");
    try {
      await op();
      await reload();
      return true;
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      return false;
    }
  };

  const patch = (u: YardUser, changes: Partial<YardUser> & { password?: string }) =>
    run(() =>
      api.updateUser(u.id, {
        display_name: changes.display_name ?? u.display_name,
        email: changes.email ?? u.email,
        role: changes.role ?? u.role,
        disabled: changes.disabled ?? u.disabled,
        password: changes.password,
      }),
    );

  const resetPassword = (u: YardUser) => {
    const pw = prompt(`New password for ${u.username} (min 8 characters):`);
    if (pw) void patch(u, { password: pw });
  };

  const add = async () => {
    const ok = await run(() =>
      api.createUser({
        username: newUser.username.trim(),
        display_name: "",
        email: "",
        role: newUser.role,
        password: newUser.password,
      }),
    );
    if (ok) setNewUser({ username: "", password: "", role: "analyst" });
  };

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal acct-modal" onClick={(e) => e.stopPropagation()}>
        <div className="acct-head">
          <h2>Users</h2>
          <button className="acct-close" onClick={onClose}>
            <Icon name="close" size={18} />
          </button>
        </div>
        {users.map((u) => (
          <div className="acct-row" key={u.id}>
            <span className="acct-name">
              {u.username}
              {u.oidc && <span className="role-badge">OIDC</span>}
              {u.disabled && <span className="role-badge">disabled</span>}
            </span>
            <select
              value={u.role}
              disabled={u.id === me.id}
              onChange={(e) => void patch(u, { role: e.target.value })}
            >
              {ROLES.map((r) => (
                <option key={r} value={r}>
                  {r}
                </option>
              ))}
            </select>
            {u.has_password && (
              <button type="button" className="linkish" onClick={() => resetPassword(u)}>
                reset pw
              </button>
            )}
            <button
              type="button"
              className="linkish"
              disabled={u.id === me.id}
              title={u.disabled ? "Enable account" : "Disable account (revokes sessions)"}
              onClick={() => void patch(u, { disabled: !u.disabled })}
            >
              {u.disabled ? "enable" : "disable"}
            </button>
            <button
              type="button"
              className="linkish"
              disabled={u.id === me.id}
              title="Delete user"
              onClick={() => {
                if (confirm(`Delete user "${u.username}"?`)) void run(() => api.deleteUser(u.id));
              }}
            >
              <Icon name="delete" size={15} />
            </button>
          </div>
        ))}

        <div className="acct-row">
          <input
            placeholder="new username"
            value={newUser.username}
            onChange={(e) => setNewUser({ ...newUser, username: e.target.value })}
          />
          <input
            type="password"
            placeholder="password (min 8)"
            value={newUser.password}
            onChange={(e) => setNewUser({ ...newUser, password: e.target.value })}
          />
          <select value={newUser.role} onChange={(e) => setNewUser({ ...newUser, role: e.target.value })}>
            {ROLES.map((r) => (
              <option key={r} value={r}>
                {r}
              </option>
            ))}
          </select>
          <button
            type="button"
            className="primary"
            disabled={!newUser.username.trim() || newUser.password.length < 8}
            onClick={() => void add()}
          >
            Add
          </button>
        </div>

        <p className="acct-hint">
          Accounts are stored in syslog-bucket and shared by every yard tool. Roles: <b>admin</b> manages
          users · <b>analyst</b> full control · <b>viewer</b> read-only.
        </p>
        {error && <div className="form-error">{error}</div>}
      </div>
    </div>
  );
}
