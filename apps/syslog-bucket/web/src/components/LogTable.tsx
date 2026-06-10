import type { Entry, Tag } from "./../types";
import { PRIORITY_NAMES, SEVERITY_NAMES } from "./../types";
import { TagChip } from "./Tags";

interface Props {
  entries: Entry[];
  tagsById: Map<number, Tag>;
  selectedId: number | null;
  onSelect: (e: Entry) => void;
  onLoadOlder: () => void;
}

function formatTime(iso: string): string {
  const d = new Date(iso);
  return d.toLocaleString(undefined, {
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

export default function LogTable({ entries, tagsById, selectedId, onSelect, onLoadOlder }: Props) {
  if (entries.length === 0) {
    return (
      <div className="logtable empty">
        <p>No entries match. Waiting for logs…</p>
        <p className="hint">
          Send a test message: <code>logger -n 127.0.0.1 -P 5514 -T --rfc3164 "hello syslog-bucket"</code>
        </p>
      </div>
    );
  }

  return (
    <div className="logtable">
      <table>
        <thead>
          <tr>
            <th className="col-time">Time</th>
            <th className="col-sev">Severity</th>
            <th className="col-pri">Pri</th>
            <th className="col-host">Host</th>
            <th className="col-app">App</th>
            <th>Message</th>
          </tr>
        </thead>
        <tbody>
          {entries.map((e) => (
            <tr
              key={e.id}
              className={`sev-${e.severity}${e.id === selectedId ? " selected" : ""}${e.suppressed ? " suppressed" : ""}${e.status === "resolved" ? " resolved" : ""}`}
              onClick={() => onSelect(e)}
            >
              <td className="col-time">{formatTime(e.received_at)}</td>
              <td className="col-sev">
                <span className={`badge sev-${e.severity}`}>{SEVERITY_NAMES[e.severity] ?? e.severity}</span>
              </td>
              <td className={`col-pri pri-${e.priority}`}>{e.priority > 0 ? PRIORITY_NAMES[e.priority] : ""}</td>
              <td className="col-host">{e.host}</td>
              <td className="col-app">{e.app_name}</td>
              <td className="col-msg">
                {(e.tag_ids ?? []).map((id) => {
                  const tag = tagsById.get(id);
                  return tag ? <TagChip key={id} tag={tag} /> : null;
                })}
                {e.msg}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      <button className="load-older" onClick={onLoadOlder}>
        Load older entries
      </button>
    </div>
  );
}
