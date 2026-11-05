// The admin-only audit log (#/audit): who changed what, from where, and
// whether it worked — sign-ins, accounts, settings, rules, buckets, tags,
// channels, frameworks and entry triage. Newest first, filterable, paged
// with the server's cursor (Previous walks back through the cursors seen).
import { useCallback, useEffect, useRef, useState } from "react";
import { useVisibleInterval } from "../../../../shared/web/src/hooks";
import { Badge, Banner, Button, EmptyState, Loading, PageHeader } from "../../../../shared/web/src/ui";
import { fetchAudit } from "./../api";
import type { AuditEvent, AuditFilters } from "./../types";

const PAGE_SIZE = 50;

// The actions the server records (internal/audit), grouped for the picker.
const ACTION_GROUPS: { label: string; actions: [string, string][] }[] = [
  {
    label: "Sign-in",
    actions: [
      ["auth.login", "Sign in"],
      ["auth.logout", "Sign out"],
      ["auth.password_change", "Own password change"],
    ],
  },
  {
    label: "Users",
    actions: [
      ["user.create", "User created"],
      ["user.update", "User changed"],
      ["user.password_reset", "Password reset by admin"],
      ["user.delete", "User deleted"],
    ],
  },
  {
    label: "Settings",
    actions: [
      ["settings.oidc", "OIDC settings"],
      ["settings.session", "Session settings"],
      ["net.config", "Network feeds"],
    ],
  },
  {
    label: "Rules",
    actions: [
      ["rule.create", "Rule created"],
      ["rule.update", "Rule changed"],
      ["rule.delete", "Rule deleted"],
      ["rule.apply", "Rule applied to history"],
    ],
  },
  {
    label: "Buckets",
    actions: [
      ["bucket.create", "Bucket created"],
      ["bucket.update", "Bucket changed"],
      ["bucket.delete", "Bucket deleted"],
      ["bucket.share", "Bucket sharing"],
    ],
  },
  {
    label: "Tags, channels, frameworks",
    actions: [
      ["tag.create", "Tag created"],
      ["tag.update", "Tag changed"],
      ["tag.delete", "Tag deleted"],
      ["channel.create", "Channel created"],
      ["channel.update", "Channel changed"],
      ["channel.delete", "Channel deleted"],
      ["framework.create", "Framework created"],
      ["framework.update", "Framework changed"],
      ["framework.delete", "Framework deleted"],
    ],
  },
  {
    label: "Triage",
    actions: [
      ["entry.update", "Status / priority"],
      ["entry.tag", "Tag added"],
      ["entry.untag", "Tag removed"],
      ["entry.classify", "Classification"],
    ],
  },
];

const ACTION_LABEL = new Map(ACTION_GROUPS.flatMap((g) => g.actions));

const TARGET_TYPES: [string, string][] = [
  ["user", "Users"],
  ["settings", "Settings"],
  ["rule", "Rules"],
  ["bucket", "Buckets"],
  ["tag", "Tags"],
  ["channel", "Channels"],
  ["framework", "Frameworks"],
  ["entry", "Entries"],
  ["net", "Network"],
];

const EMPTY: AuditFilters = { actor: "", action: "", targetType: "", result: "", since: "", until: "" };

const absFormat = new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "medium" });
const relFormat = new Intl.RelativeTimeFormat(undefined, { numeric: "auto" });

function relative(iso: string, now: number): string {
  const secs = Math.round((new Date(iso).getTime() - now) / 1000);
  const abs = Math.abs(secs);
  if (abs < 45) return "just now";
  if (abs < 3600) return relFormat.format(Math.round(secs / 60), "minute");
  if (abs < 86400) return relFormat.format(Math.round(secs / 3600), "hour");
  if (abs < 30 * 86400) return relFormat.format(Math.round(secs / 86400), "day");
  if (abs < 365 * 86400) return relFormat.format(Math.round(secs / (30 * 86400)), "month");
  return relFormat.format(Math.round(secs / (365 * 86400)), "year");
}

function show(v: unknown): string {
  if (v === null || v === undefined || v === "") return "—";
  if (Array.isArray(v)) return v.length ? v.map(show).join(", ") : "none";
  if (typeof v === "object") return JSON.stringify(v);
  return String(v);
}

// describe renders a summary as "key: value" parts; {from, to} pairs read
// as "key: from → to".
function describe(summary: Record<string, unknown> | null): string {
  if (!summary) return "";
  return Object.entries(summary)
    .map(([k, v]) => {
      const label = k.replace(/_/g, " ");
      if (v && typeof v === "object" && !Array.isArray(v) && "from" in v && "to" in v) {
        const c = v as { from: unknown; to: unknown };
        return `${label}: ${show(c.from)} → ${show(c.to)}`;
      }
      if (v === true) return label;
      return `${label}: ${show(v)}`;
    })
    .join(" · ");
}

export default function AuditPage() {
  const [filters, setFilters] = useState<AuditFilters>(EMPTY);
  const [actorDraft, setActorDraft] = useState("");
  // cursors[i] loads page i; page 0 needs none.
  const [cursors, setCursors] = useState<(string | undefined)[]>([undefined]);
  const [events, setEvents] = useState<AuditEvent[] | null>(null);
  const [next, setNext] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [now, setNow] = useState(() => Date.now());
  const [reload, setReload] = useState(0);
  const tableRef = useRef<HTMLDivElement>(null);
  const page = cursors.length - 1;

  // Relative times ("5 minutes ago") stay current while the page is open.
  useVisibleInterval(() => setNow(Date.now()), 30_000, [], { immediate: false });

  const cursor = cursors[page];
  useEffect(() => {
    let stale = false;
    setLoading(true);
    fetchAudit(filters, { cursor, limit: PAGE_SIZE })
      .then((res) => {
        if (stale) return;
        setEvents(res.events);
        setNext(res.next_cursor);
        setError(null);
        setNow(Date.now());
      })
      .catch((e) => !stale && setError(String(e)))
      .finally(() => !stale && setLoading(false));
    return () => {
      stale = true;
    };
  }, [filters, cursor, reload]);

  // Any filter change starts over at the newest page.
  const apply = useCallback((patch: Partial<AuditFilters>) => {
    setFilters((f) => ({ ...f, ...patch }));
    setCursors([undefined]);
  }, []);
  const applyActor = () => actorDraft.trim() !== filters.actor && apply({ actor: actorDraft.trim() });

  const goto = (nextCursors: (string | undefined)[]) => {
    setCursors(nextCursors);
    tableRef.current?.scrollTo({ top: 0 });
  };

  const filtered = Object.values(filters).some(Boolean);
  const clear = () => {
    setActorDraft("");
    apply(EMPTY);
  };

  return (
    <>
      <PageHeader
        title="Audit log"
        icon="history"
        meta="Who changed what, from where — newest first"
        actions={
          <Button icon="cached" onClick={() => setReload((n) => n + 1)} disabled={loading}>
            Refresh
          </Button>
        }
      />
      <div className="filterbar audit-filters" role="search" aria-label="Filter the audit log">
        <input
          type="search"
          aria-label="Actor (username)"
          placeholder="actor username"
          value={actorDraft}
          onChange={(e) => setActorDraft(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && applyActor()}
          onBlur={applyActor}
        />
        <select aria-label="Action" value={filters.action} onChange={(e) => apply({ action: e.target.value })}>
          <option value="">Any action</option>
          {ACTION_GROUPS.map((g) => (
            <optgroup key={g.label} label={g.label}>
              {g.actions.map(([id, label]) => (
                <option key={id} value={id}>
                  {label}
                </option>
              ))}
            </optgroup>
          ))}
        </select>
        <select aria-label="Target type" value={filters.targetType} onChange={(e) => apply({ targetType: e.target.value })}>
          <option value="">Any target</option>
          {TARGET_TYPES.map(([id, label]) => (
            <option key={id} value={id}>
              {label}
            </option>
          ))}
        </select>
        <select
          aria-label="Result"
          value={filters.result}
          onChange={(e) => apply({ result: e.target.value as AuditFilters["result"] })}
        >
          <option value="">Any result</option>
          <option value="success">Succeeded</option>
          <option value="failure">Failed</option>
        </select>
        <label className="audit-when">
          <span>From</span>
          <input type="datetime-local" value={filters.since} onChange={(e) => apply({ since: e.target.value })} />
        </label>
        <label className="audit-when">
          <span>To</span>
          <input type="datetime-local" value={filters.until} onChange={(e) => apply({ until: e.target.value })} />
        </label>
        {filtered && (
          <Button variant="link" icon="close" onClick={clear}>
            Clear filters
          </Button>
        )}
      </div>
      {error && (
        <Banner className="page-banner" onDismiss={() => setError(null)}>
          {error}
        </Banner>
      )}
      <div className="page audit-page" ref={tableRef}>
        {events === null ? (
          <Loading label="Loading the audit log…" />
        ) : events.length === 0 ? (
          <EmptyState icon="history" title={filtered ? "No events match these filters" : "No events recorded yet"}>
            {filtered
              ? "Try a wider time range or clear the filters."
              : "Sign-ins, account and settings changes, rule and bucket edits and triage appear here."}
          </EmptyState>
        ) : (
          <div className="table-scroll">
            <table className="data-table audit-table" aria-busy={loading}>
              <caption className="sr-only">
                Audit events, newest first, page {page + 1}. Select an actor or a target to filter by it.
              </caption>
              <thead>
                <tr>
                  <th scope="col">Time</th>
                  <th scope="col">Actor</th>
                  <th scope="col">Action</th>
                  <th scope="col">Target</th>
                  <th scope="col">Details</th>
                  <th scope="col">Result</th>
                </tr>
              </thead>
              <tbody>
                {events.map((e) => {
                  const abs = absFormat.format(new Date(e.time));
                  return (
                    <tr key={e.id} className={e.success ? undefined : "audit-failed"}>
                      <td className="audit-time">
                        <time dateTime={e.time} title={abs}>
                          {relative(e.time, now)}
                        </time>
                        <span className="audit-abs">{abs}</span>
                      </td>
                      <td>
                        {e.actor ? (
                          <Button
                            variant="link"
                            size="sm"
                            className="audit-filter-link"
                            title={`Show only events by ${e.actor}`}
                            onClick={() => {
                              setActorDraft(e.actor);
                              apply({ actor: e.actor });
                            }}
                          >
                            {e.actor}
                          </Button>
                        ) : (
                          <span className="muted">—</span>
                        )}
                        {e.actor_id === null && e.actor && <span className="muted"> (no account)</span>}
                        {e.ip && <span className="audit-ip mono">{e.ip}</span>}
                      </td>
                      <td>
                        <span className="audit-action" title={e.action}>
                          {ACTION_LABEL.get(e.action) ?? e.action}
                        </span>
                      </td>
                      <td>
                        {e.target_type ? (
                          <Button
                            variant="link"
                            size="sm"
                            className="audit-filter-link"
                            title={`Show only ${e.target_type} events`}
                            onClick={() => apply({ targetType: e.target_type })}
                          >
                            {e.target_type}
                            {e.target_id && ` #${e.target_id}`}
                          </Button>
                        ) : (
                          <span className="muted">—</span>
                        )}
                      </td>
                      <td className="audit-details">{describe(e.summary)}</td>
                      <td>
                        {e.success ? <Badge tone="success">ok</Badge> : <Badge tone="danger">failed</Badge>}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
        {events !== null && (page > 0 || next) && (
          <nav className="audit-pager" aria-label="Audit log pages">
            <Button size="sm" disabled={page === 0 || loading} onClick={() => goto(cursors.slice(0, -1))}>
              Newer
            </Button>
            <span aria-live="polite">Page {page + 1}</span>
            <Button size="sm" disabled={!next || loading} onClick={() => next && goto([...cursors, next])}>
              Older
            </Button>
          </nav>
        )}
      </div>
    </>
  );
}
