// HTTP helpers shared by every yard SPA: one way to turn an error response
// into a readable message, one session-expiry signal, one JSON request.

// ApiError carries the server's message and HTTP status. toString() is just
// the message, so String(e) in the UI reads "tag is used by rule X" rather
// than "Error: {\"error\":...}".
export class ApiError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message);
    this.name = "ApiError";
  }
  toString(): string {
    return this.message;
  }
}

// errorMessage extracts a readable message from an error response: a JSON
// {"error": "..."} (or {"message": "..."}) body, else the plain-text body
// (http.Error), else the status line.
export async function errorMessage(res: Response): Promise<string> {
  const text = (await res.text().catch(() => "")).trim();
  if (text.startsWith("{")) {
    try {
      const body = JSON.parse(text) as { error?: unknown; message?: unknown };
      const msg = body.error ?? body.message;
      if (typeof msg === "string" && msg.trim()) return msg.trim();
    } catch {
      // not JSON after all; fall through to the raw text
    }
  }
  if (res.status === 413 && !text) return "Request too large";
  return text || `HTTP ${res.status}${res.statusText ? ` ${res.statusText}` : ""}`;
}

function pathOf(url: string): string {
  try {
    return new URL(url, location.href).pathname;
  } catch {
    return url;
  }
}

// ensureOk passes a successful response through and turns any other into an
// ApiError. A 401 outside the auth endpoints means the session died mid-use
// (expired, signed out elsewhere, demoted or disabled): the app shell hears
// "auth-expired" and falls back to the login screen.
export async function ensureOk(res: Response, url = res.url): Promise<Response> {
  if (res.ok) return res;
  if (res.status === 401 && !pathOf(url).startsWith("/api/auth/")) {
    window.dispatchEvent(new Event("auth-expired"));
  }
  throw new ApiError(res.status, await errorMessage(res));
}

// request fetches url and decodes a JSON body (undefined for 204).
export async function request<T>(url: string, init?: RequestInit): Promise<T> {
  const res = await ensureOk(await fetch(url, init), url);
  if (res.status === 204) return undefined as T;
  const text = await res.text();
  return (text ? JSON.parse(text) : undefined) as T;
}

// jsonInit is a RequestInit carrying body as application/json. Every
// state-changing call with a JSON body must use it: the servers reject
// non-JSON bodies on cross-origin-looking requests.
export function jsonInit(method: string, body: unknown): RequestInit {
  return {
    method,
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  };
}

// errorText is the message to show for anything caught.
export function errorText(e: unknown): string {
  if (e instanceof Error) return e.message;
  return String(e);
}
