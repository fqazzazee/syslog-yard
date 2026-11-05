// Auth + user-management client shared by every yard SPA. The endpoints are
// served with identical shapes by all three tools: natively by syslog-bucket
// (the identity provider) and via the yardauth proxy (apps/shared/yardauth)
// in syslog-hose and syslog-valve, so one client body covers the suite.
import { jsonInit, request } from "./http";

// AuthUser comes from syslog-bucket, the yard's identity provider; auth is
// active only when the deployment sets YARD_AUTH_URL.
export interface AuthUser {
  id: number;
  username: string;
  display_name: string;
  role: string;
  has_password?: boolean;
}

// YardUser is the fuller record the bucket's user-management API returns.
export interface YardUser extends AuthUser {
  email: string;
  disabled: boolean;
  has_password: boolean;
  oidc: boolean;
}

const req = request;
const json = jsonInit;

export const authApi = {
  authInfo: () => req<{ enabled: boolean }>("/api/auth/info"),
  me: () => req<AuthUser>("/api/auth/me"),
  login: (username: string, password: string) =>
    req<AuthUser>("/api/auth/login", json("POST", { username, password })),
  logout: () => req<void>("/api/auth/logout", json("POST", {})),
  changePassword: (oldPw: string, newPw: string) =>
    req<void>("/api/auth/password", json("PUT", { old: oldPw, new: newPw })),
  users: () => req<{ users: YardUser[] }>("/api/users").then((b) => b.users),
  createUser: (u: { username: string; display_name: string; email: string; role: string; password: string }) =>
    req<YardUser>("/api/users", json("POST", u)),
  updateUser: (
    id: number,
    u: { display_name: string; email: string; role: string; disabled: boolean; password?: string },
  ) => req<YardUser>(`/api/users/${id}`, json("PUT", u)),
  deleteUser: (id: number) => req<void>(`/api/users/${id}`, { method: "DELETE" }),
};
