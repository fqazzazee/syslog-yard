import { useEffect, useRef, useState } from "react";
import { Button } from "../../../shared/web/src/ui";
import type { TailEvent } from "./api";

// TailView streams every message entering the valve (SSE from the tap
// socket), labeled with the IN port it arrived on. "drawer" is the strip
// under the canvas; "page" fills the Live tail section.
export function TailView({ variant }: { variant: "drawer" | "page" }) {
  // uid: a client-side key; the server's seq restarts with the server.
  const [events, setEvents] = useState<(TailEvent & { uid: number })[]>([]);
  const nextUid = useRef(0);
  const [paused, setPaused] = useState(false);
  const pausedRef = useRef(false);
  pausedRef.current = paused;
  const bodyRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    bodyRef.current?.scrollTo(0, bodyRef.current.scrollHeight);
  }, [events]);

  useEffect(() => {
    const es = new EventSource("/api/tail");
    es.onmessage = (m) => {
      if (pausedRef.current) return;
      let ev: TailEvent;
      try {
        ev = JSON.parse(m.data) as TailEvent;
      } catch {
        return; // skip a malformed frame
      }
      const row = { ...ev, uid: ++nextUid.current };
      setEvents((prev) => [...prev, row].slice(-300));
    };
    return () => es.close();
  }, []);

  return (
    <section className={`tail-view tail-${variant}`} aria-label="Live tail">
      <div className="tail-bar">
        <span className="muted">in-flight messages, newest last</span>
        <span className="spacer" />
        <Button size="sm" icon={paused ? "play_arrow" : "pause"} aria-pressed={paused} onClick={() => setPaused(!paused)}>
          {paused ? "Resume" : "Pause"}
        </Button>
        <Button size="sm" onClick={() => setEvents([])}>
          Clear
        </Button>
      </div>
      <div className="tail-body" ref={bodyRef} tabIndex={0} role="log" aria-live="off" aria-label="Incoming messages">
        {events.length === 0 && <div className="muted">Waiting for traffic…</div>}
        {events.map((e) => (
          <div className="tail-line" key={e.uid}>
            <span className="tail-src">{e.src}</span>
            <span className="tail-meta">
              {e.time.slice(11, 19)} {e.host} {e.program}:
            </span>{" "}
            {e.message}
          </div>
        ))}
      </div>
    </section>
  );
}
