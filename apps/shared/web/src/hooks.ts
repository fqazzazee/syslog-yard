import { useCallback, useEffect, useMemo, useRef, useState, useSyncExternalStore } from "react";
import { ensureOk } from "./http";

const STREAM_RETRY_MIN_MS = 1000;
const STREAM_RETRY_MAX_MS = 30000;

// useEventStream keeps an EventSource open and returns true while it is down.
// The browser retries a dropped connection itself but gives up for good on a
// non-200 answer (401, 503), so a closed stream is reopened here with backoff.
// EventSource can't read the status, so each retry first fetches probeUrl, a
// guarded endpoint: a 401 there raises "auth-expired" through ensureOk.
// onReopen runs when a later connection opens; the servers replay their tail
// buffer on every connection.
export function useEventStream(
  url: string,
  probeUrl: string,
  onMessage: (m: MessageEvent<string>) => void,
  onReopen?: () => void,
): boolean {
  const [down, setDown] = useState(false);
  const handlers = useRef({ onMessage, onReopen });
  handlers.current = { onMessage, onReopen };

  useEffect(() => {
    let es: EventSource;
    let timer: number | undefined;
    let stopped = false;
    let opened = false;
    let delay = STREAM_RETRY_MIN_MS;

    const retry = async () => {
      try {
        await ensureOk(await fetch(probeUrl), probeUrl);
      } catch {
        /* still down; a 401 has already signalled auth-expired */
      }
      if (stopped) return;
      timer = window.setTimeout(connect, delay);
      delay = Math.min(delay * 2, STREAM_RETRY_MAX_MS);
    };

    const connect = () => {
      es = new EventSource(url);
      es.onopen = () => {
        delay = STREAM_RETRY_MIN_MS;
        setDown(false);
        if (opened) handlers.current.onReopen?.();
        opened = true;
      };
      es.onmessage = (m: MessageEvent<string>) => handlers.current.onMessage(m);
      es.onerror = () => {
        setDown(true);
        if (es.readyState !== EventSource.CLOSED) return; // the browser is retrying
        es.close();
        void retry();
      };
    };

    connect();
    return () => {
      stopped = true;
      window.clearTimeout(timer);
      es.close();
    };
  }, [url, probeUrl]);

  return down;
}

// useVisibleInterval calls fn every ms while the tab is visible (and, unless
// immediate is false, once right away). A hidden tab stops polling; becoming
// visible again refreshes immediately and restarts the interval. fn may
// change between renders without restarting; a change in deps restarts (and
// immediately re-runs) it.
export function useVisibleInterval(
  fn: () => void,
  ms: number,
  deps: unknown[] = [],
  opts: { immediate?: boolean } = {},
): void {
  const cb = useRef(fn);
  cb.current = fn;
  const immediate = opts.immediate ?? true;
  useEffect(() => {
    let timer: number | undefined;
    const start = (now: boolean) => {
      window.clearInterval(timer);
      if (now) cb.current();
      timer = window.setInterval(() => cb.current(), ms);
    };
    const onVisibility = () => {
      if (document.visibilityState === "hidden") window.clearInterval(timer);
      else start(true);
    };
    if (document.visibilityState !== "hidden") start(immediate);
    document.addEventListener("visibilitychange", onVisibility);
    return () => {
      window.clearInterval(timer);
      document.removeEventListener("visibilitychange", onVisibility);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [ms, immediate, ...deps]);
}

// useMediaQuery tracks a CSS media query.
export function useMediaQuery(query: string): boolean {
  const subscribe = useCallback(
    (onChange: () => void) => {
      const mql = window.matchMedia(query);
      mql.addEventListener("change", onChange);
      return () => mql.removeEventListener("change", onChange);
    },
    [query],
  );
  return useSyncExternalStore(subscribe, () => window.matchMedia(query).matches);
}

// useStoredState is useState persisted to localStorage (best effort: blocked
// storage just means the value doesn't survive a reload).
export function useStoredState<T extends string>(key: string, initial: T): [T, (v: T) => void] {
  const [value, setValue] = useState<T>(() => {
    try {
      return (localStorage.getItem(key) as T | null) ?? initial;
    } catch {
      return initial;
    }
  });
  const set = useCallback(
    (v: T) => {
      setValue(v);
      try {
        localStorage.setItem(key, v);
      } catch {
        /* not persisted */
      }
    },
    [key],
  );
  return [value, set];
}

// --- hash routing -----------------------------------------------------------
//
// Every yard app routes on the URL hash (#/section/param…): the Go servers
// serve one index.html, cross-tool links can deep-link into any section,
// and back/forward walk the history like any page.

function parseHash(hash: string): string[] {
  return hash
    .replace(/^#\/?/, "")
    .split("/")
    .filter(Boolean)
    .map((p) => {
      try {
        return decodeURIComponent(p);
      } catch {
        return p;
      }
    });
}

function subscribeHash(onChange: () => void) {
  window.addEventListener("hashchange", onChange);
  window.addEventListener("popstate", onChange);
  return () => {
    window.removeEventListener("hashchange", onChange);
    window.removeEventListener("popstate", onChange);
  };
}

export type Navigate = (path: (string | number)[], opts?: { replace?: boolean }) => void;

// useHashRoute returns the current hash path segments and a navigate
// function. navigate pushes a history entry (replace: rewrites the current
// one, for redirects).
export function useHashRoute(): [string[], Navigate] {
  const hash = useSyncExternalStore(subscribeHash, () => location.hash);
  const path = useMemo(() => parseHash(hash), [hash]);
  const navigate = useCallback<Navigate>((parts, opts) => {
    const next = "#/" + parts.map((p) => encodeURIComponent(String(p))).join("/");
    if (next === location.hash) return;
    if (opts?.replace) {
      history.replaceState(history.state, "", next);
      window.dispatchEvent(new HashChangeEvent("hashchange"));
    } else {
      location.hash = next;
    }
  }, []);
  return [path, navigate];
}
