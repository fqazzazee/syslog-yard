import { useEffect, useState } from "react";
import { Dialog } from "./Dialog";
import { Icon } from "./Icon";
import { Menu, type MenuItem } from "./Menu";
import { Badge, Banner, Button, Field } from "./ui";
import { authApi as api, type AuthUser, type YardUser } from "./yardAuthApi";
import { errorText } from "./http";

// AccountMenu is the yard-wide account menu in every top bar: password
// change for everyone, user management for admins, sign out, plus any
// tool-specific items (syslog-bucket adds its admin Settings). Management
// calls go to syslog-bucket (the identity provider; hose/valve proxy them),
// which enforces roles.

const ROLES = ["admin", "analyst", "viewer"] as const;

export function AccountMenu({
  user,
  onSignOut,
  extraItems = [],
  usersDeleteNote,
}: {
  user: AuthUser;
  onSignOut: () => void;
  extraItems?: MenuItem[];
  usersDeleteNote?: string; // appended to the delete-user confirmation
}) {
  const [modal, setModal] = useState<"none" | "users" | "account">("none");
  const isAdmin = user.role === "admin";
  const items: MenuItem[] = [
    ...(isAdmin ? [{ id: "users", label: "Users…", icon: "manage_accounts" as const, onSelect: () => setModal("users") }] : []),
    ...extraItems,
    { id: "account", label: "Account…", icon: "account_circle", onSelect: () => setModal("account") },
    { id: "signout", label: "Sign out", icon: "logout", onSelect: onSignOut },
  ];

  return (
    <>
      <Menu
        className="user-menu"
        triggerClassName="user-btn"
        label={`Account: ${user.display_name || user.username} (${user.role})`}
        trigger={
          <>
            <Icon name="account_circle" size={18} />
            <span className="user-btn-name">{user.display_name || user.username}</span>
            <span className={`role-badge role-${user.role}`}>{user.role}</span>
            <Icon name="keyboard_arrow_down" size={16} className="caret" />
          </>
        }
        items={items}
      />
      {modal === "account" && <AccountDialog user={user} onClose={() => setModal("none")} />}
      {modal === "users" && <UsersDialog me={user} deleteNote={usersDeleteNote} onClose={() => setModal("none")} />}
    </>
  );
}

function AccountDialog({ user, onClose }: { user: AuthUser; onClose: () => void }) {
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
      setError(errorText(e));
    }
  };

  const canSave = !!oldPw && newPw.length >= 8 && !done;
  return (
    <Dialog
      title={`Account — ${user.username}`}
      size="sm"
      onClose={onClose}
      footer={
        user.has_password ? (
          <Button variant="primary" type="submit" form="yard-account-form" disabled={!canSave}>
            Change password
          </Button>
        ) : undefined
      }
    >
      {user.has_password ? (
        <form
          id="yard-account-form"
          className="form-stack"
          onSubmit={(e) => {
            e.preventDefault();
            if (canSave) void save();
          }}
        >
          <Field label="Current password">
            <input type="password" autoComplete="current-password" value={oldPw} onChange={(e) => setOldPw(e.target.value)} autoFocus />
          </Field>
          <Field label="New password" help="At least 8 characters.">
            <input type="password" autoComplete="new-password" value={newPw} onChange={(e) => setNewPw(e.target.value)} />
          </Field>
          <Field label="Repeat new password">
            <input type="password" autoComplete="new-password" value={confirmPw} onChange={(e) => setConfirmPw(e.target.value)} />
          </Field>
          {error && <Banner kind="error">{error}</Banner>}
          {done && <Banner kind="success">Password changed — other sessions were signed out.</Banner>}
        </form>
      ) : (
        <p className="hint">This account signs in via OIDC; manage its password at your identity provider.</p>
      )}
    </Dialog>
  );
}

function UsersDialog({ me, deleteNote, onClose }: { me: AuthUser; deleteNote?: string; onClose: () => void }) {
  const [users, setUsers] = useState<YardUser[]>([]);
  const [error, setError] = useState("");
  const [newUser, setNewUser] = useState({ username: "", password: "", role: "analyst" as string });

  const reload = () => api.users().then(setUsers).catch((e: unknown) => setError(errorText(e)));
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
      setError(errorText(e));
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
    <Dialog title="Users" onClose={onClose}>
      <div className="table-scroll">
        <table className="data-table users-table">
          <thead>
            <tr>
              <th scope="col">User</th>
              <th scope="col">Role</th>
              <th scope="col">
                <span className="sr-only">Actions</span>
              </th>
            </tr>
          </thead>
          <tbody>
            {users.map((u) => (
              <tr key={u.id}>
                <td>
                  <span className="users-name">
                    {u.username}
                    {u.oidc && <Badge>OIDC</Badge>}
                    {u.disabled && <Badge tone="warning">disabled</Badge>}
                  </span>
                </td>
                <td>
                  <select
                    aria-label={`Role of ${u.username}`}
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
                </td>
                <td className="row-actions">
                  {u.has_password && (
                    <Button variant="link" size="sm" onClick={() => resetPassword(u)} aria-label={`Reset password of ${u.username}`}>
                      reset pw
                    </Button>
                  )}
                  <Button
                    variant="link"
                    size="sm"
                    disabled={u.id === me.id}
                    title={u.disabled ? "Enable account" : "Disable account (revokes sessions)"}
                    aria-label={`${u.disabled ? "Enable" : "Disable"} ${u.username}`}
                    onClick={() => void patch(u, { disabled: !u.disabled })}
                  >
                    {u.disabled ? "enable" : "disable"}
                  </Button>
                  <Button
                    variant="link"
                    size="sm"
                    icon="delete"
                    disabled={u.id === me.id}
                    title="Delete user"
                    aria-label={`Delete ${u.username}`}
                    onClick={() => {
                      if (confirm(`Delete user "${u.username}"?${deleteNote ? ` ${deleteNote}` : ""}`)) void run(() => api.deleteUser(u.id));
                    }}
                  />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <form
        className="users-add"
        onSubmit={(e) => {
          e.preventDefault();
          if (newUser.username.trim() && newUser.password.length >= 8) void add();
        }}
      >
        <input
          aria-label="New username"
          placeholder="new username"
          autoComplete="off"
          value={newUser.username}
          onChange={(e) => setNewUser({ ...newUser, username: e.target.value })}
        />
        <input
          aria-label="Password (min 8 characters)"
          type="password"
          placeholder="password (min 8)"
          autoComplete="new-password"
          value={newUser.password}
          onChange={(e) => setNewUser({ ...newUser, password: e.target.value })}
        />
        <select aria-label="Role" value={newUser.role} onChange={(e) => setNewUser({ ...newUser, role: e.target.value })}>
          {ROLES.map((r) => (
            <option key={r} value={r}>
              {r}
            </option>
          ))}
        </select>
        <Button type="submit" variant="primary" icon="add" disabled={!newUser.username.trim() || newUser.password.length < 8}>
          Add
        </Button>
      </form>

      <p className="hint">
        Accounts are stored in syslog-bucket and shared by every yard tool. Roles: <b>admin</b> manages users and all
        buckets · <b>analyst</b> full control · <b>viewer</b> read-only.
      </p>
      {error && <Banner kind="error">{error}</Banner>}
    </Dialog>
  );
}
