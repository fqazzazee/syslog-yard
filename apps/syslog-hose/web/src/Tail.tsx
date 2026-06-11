import { useEffect, useRef, useState } from "react";
import { Job, TailEvent } from "./api";
import { Icon } from "./Icon";

export function Tail(props: {
  events: TailEvent[];
  jobs: Job[];
  visible: boolean;
  onToggle: () => void;
  onPause: (paused: boolean) => void;
  onClear: () => void;
}) {
  const [filter, setFilter] = useState("");
  const [paused, setPaused] = useState(false);
  const endRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (props.visible && !paused) {
      endRef.current?.scrollIntoView({ behavior: "instant", block: "end" });
    }
  }, [props.events, props.visible, paused]);

  const shown = filter ? props.events.filter((e) => e.jobId === filter) : props.events;

  return (
    <div className={props.visible ? "tail open" : "tail"}>
      <div className="tail-bar">
        <button className="quiet" onClick={props.onToggle}>
          <Icon name={props.visible ? "keyboard_arrow_down" : "keyboard_arrow_up"} size={16} /> Live tail
        </button>
        {props.visible && (
          <>
            <select value={filter} onChange={(e) => setFilter(e.target.value)}>
              <option value="">All jobs</option>
              {props.jobs.map((j) => (
                <option key={j.id} value={j.id}>
                  {j.name}
                </option>
              ))}
            </select>
            <button
              className="quiet"
              onClick={() => {
                const p = !paused;
                setPaused(p);
                props.onPause(p);
              }}
            >
              <Icon name={paused ? "play_arrow" : "pause"} size={15} /> {paused ? "Resume" : "Pause"}
            </button>
            <button className="quiet" onClick={props.onClear}>
              Clear
            </button>
            <span className="dim">{shown.length} events buffered</span>
          </>
        )}
      </div>
      {props.visible && (
        <div className="tail-body">
          {shown.map((e) => (
            <div key={e.seq} className="tail-line">
              <span className="tail-job">{e.jobName}</span>
              <span className="tail-msg">{e.message}</span>
            </div>
          ))}
          <div ref={endRef} />
        </div>
      )}
    </div>
  );
}
