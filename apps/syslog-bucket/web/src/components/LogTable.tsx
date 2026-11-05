// The log table: virtualized (only the rows near the viewport are in the
// DOM, see shared virtual.ts), so a few thousand entries scroll smoothly.
//
// Keyboard triage: one row is in the tab order (roving tabindex); arrow
// keys or j/k, PageUp/PageDown and Home/End move between rows, scrolling the
// target into view and rendering it first if needed; Enter or Space opens
// a row, Escape closes the details. If the focused row scrolls out of the
// window, focus parks on the scroll container and the same keys carry on
// from that row.
//
// While the reader is scrolled away from the top of the newest-first
// order, live arrivals don't move the view; a "N new" pill counts them and
// scrolls back up.
import { memo, useCallback, useLayoutEffect, useMemo, useRef, useState, type KeyboardEvent } from "react";
import { Button, EmptyState } from "../../../../shared/web/src/ui";
import { useVirtualRows } from "../../../../shared/web/src/virtual";
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

const PAGE_ROWS = 10;

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

export default function LogTable(props: Props) {
  if (props.entries.length === 0) {
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
  return <Rows {...props} />;
}

function Rows({
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
  const scrollRef = useRef<HTMLDivElement>(null);
  const tbodyRef = useRef<HTMLTableSectionElement>(null);
  const keys = useMemo(() => entries.map((e) => e.id), [entries]);
  const v = useVirtualRows({ scrollRef, bodyRef: tbodyRef, keys, resetKey: `${sort}:${desc}` });

  // Stable handlers for the memoized rows.
  const selectRef = useRef(onSelect);
  selectRef.current = onSelect;
  const techniqueRef = useRef(onSelectTechnique);
  techniqueRef.current = onSelectTechnique;
  const select = useCallback((e: Entry) => selectRef.current(e), []);
  const selectTechnique = useCallback((id: string) => techniqueRef.current(id), []);

  // Roving tabindex: the selected row, else the last focused, else the
  // first. A row outside the rendered window can't hold the tab stop, so
  // then the first rendered row does.
  const [focusId, setFocusId] = useState<number | null>(null);
  const indexOf = (id: number | null) => (id === null ? -1 : keys.indexOf(id));
  const tabIndex = indexOf(selectedId) >= 0 ? indexOf(selectedId) : indexOf(focusId) >= 0 ? indexOf(focusId) : 0;
  const tabbable = tabIndex >= v.start && tabIndex < v.end ? keys[tabIndex] : keys[v.start];

  // Keyboard moves focus to a row that may not be rendered yet: remember
  // it, scroll it into view, focus it after the render that adds it.
  const pendingFocus = useRef<number | null>(null);
  // The row that had focus, to park focus on the scroller if it unmounts.
  const focusedRow = useRef<number | null>(null);

  useLayoutEffect(() => {
    const el = scrollRef.current;
    const body = tbodyRef.current;
    if (!el || !body) return;
    const id = pendingFocus.current;
    if (id !== null) {
      const row = body.querySelector<HTMLElement>(`tr[data-id="${id}"]`);
      if (row) {
        pendingFocus.current = null;
        row.focus({ preventScroll: true });
        // Exact reveal now that the row has its real height (the sticky
        // header covers the top of the scroller).
        const r = row.getBoundingClientRect();
        const s = el.getBoundingClientRect();
        const headH = body.getBoundingClientRect().top - s.top + el.scrollTop;
        if (r.top < s.top + headH) el.scrollTop -= s.top + headH - r.top;
        else if (r.bottom > s.top + el.clientHeight) el.scrollTop += r.bottom - (s.top + el.clientHeight);
      }
    } else if (
      focusedRow.current !== null &&
      document.activeElement === document.body &&
      !body.querySelector(`tr[data-id="${focusedRow.current}"]`)
    ) {
      el.focus({ preventScroll: true });
    }
  });

  const moveTo = (i: number) => {
    const e = entries[i];
    if (!e) return;
    setFocusId(e.id);
    pendingFocus.current = e.id;
    v.scrollToIndex(i);
    // With the detail pane open, the selection follows the keyboard.
    if (selectedId !== null) select(e);
  };

  const onKey = (ev: KeyboardEvent<HTMLDivElement>) => {
    const t = ev.target as HTMLElement;
    let i: number;
    if (t.tagName === "TR" && t.dataset.id) i = indexOf(Number(t.dataset.id));
    else if (t === scrollRef.current) i = tabIndex; // focus parked on the scroller
    else return; // keys inside a chip button, the header, etc.
    if (i < 0) return;
    const last = entries.length - 1;
    let next: number;
    switch (ev.key) {
      case "ArrowDown":
      case "j":
        next = Math.min(i + 1, last);
        break;
      case "ArrowUp":
      case "k":
        next = Math.max(i - 1, 0);
        break;
      case "PageDown":
        next = Math.min(i + PAGE_ROWS, last);
        break;
      case "PageUp":
        next = Math.max(i - PAGE_ROWS, 0);
        break;
      case "Home":
        next = 0;
        break;
      case "End":
        next = last;
        break;
      case "Enter":
      case " ":
        ev.preventDefault();
        select(entries[i]);
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
    moveTo(next);
  };

  // "N new": entries newer than what the reader last saw at the top. Only
  // in newest-first time order, where arrivals land at the top.
  const liveOrder = sort === "time" && desc;
  const newest = keys[0] ?? 0;
  const [seenNewest, setSeenNewest] = useState(newest);
  useLayoutEffect(() => {
    if ((v.atTop || !liveOrder) && seenNewest !== newest) setSeenNewest(newest);
  }, [v.atTop, liveOrder, newest, seenNewest]);
  let fresh = 0;
  if (liveOrder && !v.atTop) while (fresh < keys.length && keys[fresh] > seenNewest) fresh++;

  // A sortable header: a button inside the th, so it is keyboard
  // reachable; aria-sort tells assistive tech the current order. (A plain
  // function, not a component, so a focused header button survives the
  // re-renders scrolling causes.)
  const th = (k: SortKey, label: string, cls?: string) => (
    <th key={k} scope="col" className={cls} aria-sort={sort === k ? (desc ? "descending" : "ascending") : "none"}>
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

  // "Load older" only makes sense in time order; a column sort returns a
  // single ranked page.
  const timeSort = sort === "time";
  const rows = entries.slice(v.start, v.end);

  return (
    <div className="logpane">
      <div className="logtable" ref={scrollRef} tabIndex={-1} onKeyDown={onKey}>
        <table className="data-table" aria-rowcount={entries.length + 1}>
          <caption className="sr-only">
            Log entries. Arrow keys or j and k move between rows, Enter opens one, Escape closes the details.
          </caption>
          <thead>
            <tr aria-rowindex={1}>
              {th("time", "Time", "col-time")}
              {th("severity", "Severity", "col-sev")}
              {th("priority", "Pri", "col-pri")}
              {th("host", "Host", "col-host")}
              {th("app", "App", "col-app")}
              {th("device_class", "Class", "col-class")}
              <th scope="col">Message</th>
            </tr>
          </thead>
          <tbody
            ref={tbodyRef}
            onFocus={(ev) => {
              const id = (ev.target as HTMLElement).dataset.id;
              if (id) {
                focusedRow.current = Number(id);
                setFocusId(Number(id));
              }
            }}
            onBlur={(ev) => {
              // Focus moved somewhere else on purpose (not a row unmounting).
              if (ev.relatedTarget && !tbodyRef.current?.contains(ev.relatedTarget as Node)) focusedRow.current = null;
            }}
          >
            {v.padTop > 0 && <Spacer height={v.padTop} />}
            {rows.map((e, j) => (
              <Row
                key={e.id}
                e={e}
                rowIndex={v.start + j + 2}
                tagsById={tagsById}
                selected={e.id === selectedId}
                tabbable={e.id === tabbable}
                onSelect={select}
                onSelectTechnique={selectTechnique}
              />
            ))}
            {v.padBottom > 0 && <Spacer height={v.padBottom} />}
          </tbody>
        </table>
        {timeSort && (
          <Button className="load-older" onClick={onLoadOlder} disabled={olderState !== "idle"}>
            {olderState === "loading" ? "Loading…" : olderState === "end" ? "No older entries" : "Load older entries"}
          </Button>
        )}
      </div>
      {fresh > 0 && (
        <button
          type="button"
          className="new-pill"
          onClick={() => {
            v.scrollToTop();
            setFocusId(keys[0]);
            pendingFocus.current = keys[0];
          }}
        >
          <Icon name="keyboard_arrow_up" size={16} />
          {fresh.toLocaleString()} new
        </button>
      )}
    </div>
  );
}

// One cell, no colSpan: the table sheds columns as it narrows (styles.css
// container queries), and a span wider than the visible columns would add
// empty ones.
function Spacer({ height }: { height: number }) {
  return (
    <tr className="vpad" aria-hidden="true">
      <td style={{ height }} />
    </tr>
  );
}

const Row = memo(function Row({
  e,
  rowIndex,
  tagsById,
  selected,
  tabbable,
  onSelect,
  onSelectTechnique,
}: {
  e: Entry;
  rowIndex: number;
  tagsById: Map<number, Tag>;
  selected: boolean;
  tabbable: boolean;
  onSelect: (e: Entry) => void;
  onSelectTechnique: (id: string) => void;
}) {
  return (
    <tr
      data-id={e.id}
      aria-rowindex={rowIndex}
      tabIndex={tabbable ? 0 : -1}
      aria-current={selected ? "true" : undefined}
      className={`sev-${e.severity}${selected ? " selected" : ""}${e.suppressed ? " suppressed" : ""}${e.status === "resolved" ? " resolved" : ""}`}
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
  );
});
