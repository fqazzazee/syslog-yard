import { useEffect, useRef, useState } from "react";
import { Button } from "../../../shared/web/src/ui";
import type { Job, TailEvent } from "./api";

// TailRow is a TailEvent plus a client-assigned key. The server's seq is not
// unique across a server restart (the browser keeps its buffer), so it
// can't be the React key on its own.
export type TailRow = TailEvent & { uid: number };

// Tail shows what the running jobs send. variant "drawer" is the
// collapsible strip under the Jobs page; "page" fills the Live tail section.
export function Tail(props: {
  events: TailRow[];
  jobs: Job[];
  paused: boolean;
  onPause: (paused: boolean) => void;
  onClear: () => void;
  variant: "drawer" | "page";
  open?: boolean;
  onToggle?: () => void;
}) {
  const [filter, setFilter] = useState("");
  const bodyRef = useRef<HTMLDivElement>(null);
  const visible = props.variant === "page" || !!props.open;

  useEffect(() => {
    const el = bodyRef.current;
    if (visible && !props.paused && el) el.scrollTop = el.scrollHeight;
  }, [props.events, visible, props.paused]);

  const shown = filter ? props.events.filter((e) => e.jobId === filter) : props.events;

  return (
    <section className={`tail tail-${props.variant}${visible ? " open" : ""}`} aria-label="Live tail">
      <div className="tail-bar">
        {props.variant === "drawer" && (
          <Button
            variant="quiet"
            icon={visible ? "keyboard_arrow_down" : "keyboard_arrow_up"}
            aria-expanded={visible}
            aria-controls="hose-tail-body"
            onClick={props.onToggle}
          >
            Live tail
          </Button>
        )}
        {visible && (
          <>
            <select aria-label="Show job" value={filter} onChange={(e) => setFilter(e.target.value)}>
              <option value="">All jobs</option>
              {props.jobs.map((j) => (
                <option key={j.id} value={j.id}>
                  {j.name}
                </option>
              ))}
            </select>
            <Button
              variant="quiet"
              icon={props.paused ? "play_arrow" : "pause"}
              aria-pressed={props.paused}
              onClick={() => props.onPause(!props.paused)}
            >
              {props.paused ? "Resume" : "Pause"}
            </Button>
            <Button variant="quiet" onClick={props.onClear}>
              Clear
            </Button>
            <span className="tail-count">{shown.length} events buffered</span>
          </>
        )}
      </div>
      {visible && (
        <div className="tail-body" id="hose-tail-body" ref={bodyRef} tabIndex={0} role="log" aria-live="off" aria-label="Sent messages">
          {shown.length === 0 && <div className="tail-empty">Waiting for a running job…</div>}
          {shown.map((e) => (
            <div key={e.uid} className="tail-line">
              <span className="tail-job">{e.jobName}</span>
              <span className="tail-msg">{e.message}</span>
            </div>
          ))}
        </div>
      )}
    </section>
  );
}
