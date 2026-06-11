import type { Entry, SortKey, Tag } from "./../types";
import { PRIORITY_NAMES, SEVERITY_NAMES } from "./../types";
import { TagChip } from "./Tags";

interface Props {
  entries: Entry[];
  tagsById: Map<number, Tag>;
  selectedId: number | null;
  sort: SortKey;
  desc: boolean;
  onSort: (key: SortKey) => void;
  onSelect: (e: Entry) => void;
  onSelectTechnique: (id: string) => void;
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

export default function LogTable({
  entries,
  tagsById,
  selectedId,
  sort,
  desc,
  onSort,
  onSelect,
  onSelectTechnique,
  onLoadOlder,
}: Props) {
  // A clickable header: click toggles direction when already active, else
  // selects that column (descending by default).
  const Th = ({ k, label, cls }: { k: SortKey; label: string; cls?: string }) => (
    <th className={`${cls ?? ""} sortable${sort === k ? " sorted" : ""}`} onClick={() => onSort(k)}>
      {label}
      {sort === k && <span className="sort-arrow">{desc ? " ▾" : " ▴"}</span>}
    </th>
  );

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

  // "Load older" only makes sense in time order; a column sort returns a
  // single ranked page.
  const timeSort = sort === "time";

  return (
    <div className="logtable">
      <table>
        <thead>
          <tr>
            <Th k="time" label="Time" cls="col-time" />
            <Th k="severity" label="Severity" cls="col-sev" />
            <Th k="priority" label="Pri" cls="col-pri" />
            <Th k="host" label="Host" cls="col-host" />
            <Th k="app" label="App" cls="col-app" />
            <Th k="device_class" label="Class" cls="col-class" />
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
              <td className="col-class">{e.device_class || ""}</td>
              <td className="col-msg">
                {(e.tag_ids ?? []).map((id) => {
                  const tag = tagsById.get(id);
                  return tag ? <TagChip key={id} tag={tag} /> : null;
                })}
                {(e.mitre ?? []).map((id) => (
                  <button
                    key={id}
                    className="mitre-chip"
                    title={`MITRE ATT&CK ${id} — click to filter`}
                    onClick={(ev) => {
                      ev.stopPropagation();
                      onSelectTechnique(id);
                    }}
                  >
                    {id}
                  </button>
                ))}
                {e.msg}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      {timeSort && (
        <button className="load-older" onClick={onLoadOlder}>
          Load older entries
        </button>
      )}
    </div>
  );
}
