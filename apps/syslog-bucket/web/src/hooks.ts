import { useEffect, useRef, useState } from "react";
import type { Entry } from "./types";

// useLiveTail keeps a WebSocket open to /api/ws (reconnecting with backoff)
// and feeds matching entries to onEntry. Pass url=null to pause.
export function useLiveTail(url: string | null, onEntry: (e: Entry) => void): boolean {
  const cb = useRef(onEntry);
  cb.current = onEntry;
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
      };
      ws.onmessage = (ev) => {
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
