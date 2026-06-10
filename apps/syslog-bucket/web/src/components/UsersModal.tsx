import { useEffect, useState } from "react";
import { createUser, deleteUser, fetchUsers, updateUser } from "./../api";
import type { Role, User } from "./../types";
import Modal from "./Modal";

const ROLES: Role[] = ["admin", "analyst", "viewer"];

interface Props {
  me: User;
  onClose: () => void;
}

// Admin-only user management: add local accounts, change roles, disable,
// reset passwords, delete. OIDC accounts appear once their owner first
// signs in and can be role-managed like any other.
export default function UsersModal({ me, onClose }: Props) {
  const [users, setUsers] = useState<User[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [newUser, setNewUser] = useState({ username: "", password: "", role: "analyst" as Role });

  const reload = () => fetchUsers().then(setUsers).catch((e) => setError(String(e)));
  useEffect(() => {
    void reload();
  }, []);

  const run = async (op: () => Promise<unknown>) => {
    setError(null);
    try {
      await op();
      await reload();
      return true;
    } catch (e) {
      setError(String(e instanceof Error ? e.message : e));
      return false;
    }
  };

  const patch = (u: User, changes: Partial<User> & { password?: string }) =>
    run(() =>
      updateUser(u.id, {
        display_name: changes.display_name ?? u.display_name,
        email: changes.email ?? u.email,
        role: changes.role ?? u.role,
        disabled: changes.disabled ?? u.disabled,
        password: changes.password,
      }),
    );

  const resetPassword = (u: User) => {
    const pw = prompt(`New password for ${u.username} (min 8 characters):`);
    if (pw) void patch(u, { password: pw });
  };

  const add = async () => {
    const ok = await run(() =>
      createUser({ username: newUser.username.trim(), display_name: "", email: "", role: newUser.role, password: newUser.password }),
    );
    if (ok) setNewUser({ username: "", password: "", role: "analyst" });
  };

  return (
    <Modal title="Users" onClose={onClose}>
      {users.map((u) => (
        <div className="cond-row user-row" key={u.id}>
          <span className="user-name">
            {u.username}
            {u.oidc && <span className="badge muted">OIDC</span>}
            {u.disabled && <span className="badge muted">disabled</span>}
          </span>
          <select
            value={u.role}
            disabled={u.id === me.id}
            onChange={(e) => void patch(u, { role: e.target.value as Role })}
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
              if (confirm(`Delete user "${u.username}"? Their buckets become ownerless yard buckets.`))
                void run(() => deleteUser(u.id));
            }}
          >
            ✕
          </button>
        </div>
      ))}

      <div className="cond-row user-row">
        <input
          className="cond-value"
          placeholder="new username"
          value={newUser.username}
          onChange={(e) => setNewUser({ ...newUser, username: e.target.value })}
        />
        <input
          className="cond-value"
          type="password"
          placeholder="password (min 8)"
          value={newUser.password}
          onChange={(e) => setNewUser({ ...newUser, password: e.target.value })}
        />
        <select value={newUser.role} onChange={(e) => setNewUser({ ...newUser, role: e.target.value as Role })}>
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

      <p className="hint">
        Roles: <b>admin</b> manages users and all buckets · <b>analyst</b> full triage ·{" "}
        <b>viewer</b> read-only.
      </p>
      {error && <div className="error">{error}</div>}
    </Modal>
  );
}
