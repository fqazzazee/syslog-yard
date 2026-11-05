import { useRef, useState, type KeyboardEvent } from "react";
import { Button, EmptyState } from "../../../../shared/web/src/ui";
import type { Entry, SortKey, Tag } from "./../types";
import { PRIORITY_NAMES, SEVERITY_NAMES } from "./../types";
import { Icon } from "./Icon";
import { TagChip } from "./Tags";

interface Props {
  entries: Entry[];
  tagsById: Map<number, Tag>;
  selectedId: number | null;
  sort: SortKey;
  desc: boolean;
  onSort: (key: SortKey) => void;
  onSelect: (e: Entry) => void;
  onDeselect: () => void;
  onSelectTechnique: (id: string) => void;
  olderState: "idle" | "loading" | "end";
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
  onDeselect,
  onSelectTechnique,
  olderState,
  onLoadOlder,
}: Props) {
  const tbodyRef = useRef<HTMLTableSectionElement>(null);
  // Roving tabindex: one row is in the tab order (the selected one, else the
  // last focused, else the first); arrow keys / j k move between rows.
  const [focusId, setFocusId] = useState<number | null>(null);
  const rowIds = entries.map((e) => e.id);
  const tabId =
    selectedId !== null && rowIds.includes(selectedId)
      ? selectedId
      : focusId !== null && rowIds.includes(focusId)
        ? focusId
        : (rowIds[0] ?? null);

  // A sortable header: a button inside the th, so it is keyboard
  // reachable; aria-sort tells assistive tech the current order.
  const Th = ({ k, label, cls }: { k: SortKey; label: string; cls?: string }) => (
    <th
      scope="col"
      className={cls}
      aria-sort={sort === k ? (desc ? "descending" : "ascending") : "none"}
    >
      <button type="button" className="th-sort" onClick={() => onSort(k)} title={`Sort by ${label.toLowerCase()}`}>
        {label}
        {sort === k && (
          <span className="sort-arrow" aria-hidden="true">
            <Icon name={desc ? "keyboard_arrow_down" : "keyboard_arrow_up"} size={14} />
          </span>
        )}
      </button>
    </th>
  );

  const onRowKey = (ev: KeyboardEvent<HTMLTableSectionElement>) => {
    const row = ev.target as HTMLElement;
    if (row.tagName !== "TR") return; // keys inside a chip button etc.
    const id = Number(row.dataset.id);
    const i = entries.findIndex((e) => e.id === id);
    if (i < 0) return;
    let next = -1;
    switch (ev.key) {
      case "ArrowDown":
      case "j":
        next = Math.min(i + 1, entries.length - 1);
        break;
      case "ArrowUp":
      case "k":
        next = Math.max(i - 1, 0);
        break;
      case "PageDown":
        next = Math.min(i + 10, entries.length - 1);
        break;
      case "PageUp":
        next = Math.max(i - 10, 0);
        break;
      case "Home":
        next = 0;
        break;
      case "End":
        next = entries.length - 1;
        break;
      case "Enter":
      case " ":
        ev.preventDefault();
        onSelect(entries[i]);
        return;
      case "Escape":
        if (selectedId !== null) {
          ev.preventDefault();
          onDeselect();
        }
        return;
      default:
        return;
    }
    ev.preventDefault();
    const e = entries[next];
    setFocusId(e.id);
    tbodyRef.current?.querySelector<HTMLElement>(`tr[data-id="${e.id}"]`)?.focus();
    // With the detail pane open, the selection follows the keyboard.
    if (selectedId !== null) onSelect(e);
  };

  if (entries.length === 0) {
    return (
      <div className="logtable empty">
        <EmptyState icon="inbox" title="No entries match">
          <p>Waiting for logs… Send a test message:</p>
          <p>
            <code>logger -n 127.0.0.1 -P 5514 -T --rfc3164 "hello syslog-bucket"</code>
          </p>
        </EmptyState>
      </div>
    );
  }

  // "Load older" only makes sense in time order; a column sort returns a
  // single ranked page.
  const timeSort = sort === "time";

  return (
    <div className="logtable">
      <table className="data-table">
        <caption className="sr-only">
          Log entries. Arrow keys or j and k move between rows, Enter opens one, Escape closes the details.
        </caption>
        <thead>
          <tr>
            <Th k="time" label="Time" cls="col-time" />
            <Th k="severity" label="Severity" cls="col-sev" />
            <Th k="priority" label="Pri" cls="col-pri" />
            <Th k="host" label="Host" cls="col-host" />
            <Th k="app" label="App" cls="col-app" />
            <Th k="device_class" label="Class" cls="col-class" />
            <th scope="col">Message</th>
          </tr>
        </thead>
        <tbody ref={tbodyRef} onKeyDown={onRowKey}>
          {entries.map((e) => (
            <tr
              key={e.id}
              data-id={e.id}
              tabIndex={e.id === tabId ? 0 : -1}
              aria-current={e.id === selectedId ? "true" : undefined}
              onFocus={(ev) => ev.target === ev.currentTarget && setFocusId(e.id)}
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
                    type="button"
                    tabIndex={-1}
                    className="mitre-chip"
                    title={`MITRE ATT&CK ${id} — show its entries`}
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
        <Button className="load-older" onClick={onLoadOlder} disabled={olderState !== "idle"}>
          {olderState === "loading"
            ? "Loading…"
            : olderState === "end"
              ? "No older entries"
              : "Load older entries"}
        </Button>
      )}
    </div>
  );
}
