import { useEffect, useRef, useState } from "react";
import type { Entry } from "./types";

// useLiveTail keeps a WebSocket open to /api/ws (reconnecting with backoff)
// and feeds matching entries to onEntry. Pass url=null to pause. onOpen runs
// on every (re)connect so the caller can backfill whatever it missed while
// the socket was down — the server only pushes entries from then on.
export function useLiveTail(
  url: string | null,
  onEntry: (e: Entry) => void,
  onOpen?: () => void,
): boolean {
  const cb = useRef(onEntry);
  cb.current = onEntry;
  const openCb = useRef(onOpen);
  openCb.current = onOpen;
  const [open, setOpen] = useState(false);

  useEffect(() => {
    if (!url) {
      setOpen(false);
      return;
    }
    let ws: WebSocket | null = null;
    let timer: number | undefined;
    let stopped = false;
    let delay = 1000;

    const connect = () => {
      ws = new WebSocket(url);
      ws.onopen = () => {
        delay = 1000;
        setOpen(true);
        openCb.current?.();
      };
      ws.onmessage = (ev) => {
        if (stopped) return;
        try {
          const msg = JSON.parse(ev.data as string) as { type: string; entry: Entry };
          if (msg.type === "entry") cb.current(msg.entry);
        } catch {
          // ignore malformed frames
        }
      };
      ws.onclose = () => {
        setOpen(false);
        if (stopped) return;
        timer = window.setTimeout(connect, delay);
        delay = Math.min(delay * 2, 15_000);
      };
    };
    connect();
    return () => {
      stopped = true;
      window.clearTimeout(timer);
      ws?.close();
      setOpen(false);
    };
  }, [url]);

  return open;
}

// useVisibleInterval calls fn now and every ms while the tab is visible. A
// hidden tab stops polling; becoming visible again refreshes immediately and
// restarts the interval. fn may change between renders without restarting;
// a change in deps restarts (and immediately re-runs) it.
export function useVisibleInterval(fn: () => void, ms: number, deps: unknown[] = []): void {
  const cb = useRef(fn);
  cb.current = fn;
  useEffect(() => {
    let timer: number | undefined;
    const start = () => {
      window.clearInterval(timer);
      cb.current();
      timer = window.setInterval(() => cb.current(), ms);
    };
    const onVisibility = () => {
      if (document.visibilityState === "hidden") window.clearInterval(timer);
      else start();
    };
    if (document.visibilityState !== "hidden") start();
    document.addEventListener("visibilitychange", onVisibility);
    return () => {
      window.clearInterval(timer);
      document.removeEventListener("visibilitychange", onVisibility);
    };
  }, [ms, ...deps]);
}
