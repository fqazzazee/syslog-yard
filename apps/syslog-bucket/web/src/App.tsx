import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  fetchAuthInfo,
  fetchBuckets,
  fetchChannels,
  fetchEntries,
  fetchFrameworks,
  fetchHints,
  fetchMe,
  fetchMitre,
  fetchOt,
  fetchRules,
  fetchStats,
  fetchTags,
  liveTailURL,
  logout,
} from "./api";
import type {
  Action,
  AuthInfo,
  Bucket,
  Channel,
  Cond,
  Entry,
  Filters,
  Framework,
  IngestStats,
  MitreCatalog,
  OTCatalog,
  Rule,
  Selection,
  SortKey,
  Stats,
  Tag,
  User,
} from "./types";
import { AppShell } from "../../../shared/web/src/AppShell";
import { useHashRoute } from "../../../shared/web/src/hooks";
import { ApiError } from "../../../shared/web/src/http";
import { Login } from "../../../shared/web/src/Login";
import { Badge, Banner, Button, Loading, PageHeader } from "../../../shared/web/src/ui";
import type { IconName } from "../../../shared/web/src/Icon";
import BucketModal from "./components/BucketModal";
import ChannelsModal from "./components/ChannelsModal";
import EntryDetail from "./components/EntryDetail";
import FilterBar from "./components/FilterBar";
import FrameworkEditor from "./components/FrameworkEditor";
import FrameworkView from "./components/FrameworkView";
import { BucketsPage, FrameworksPage, RulesPage } from "./components/ListPages";
import LogTable from "./components/LogTable";
import MitreView from "./components/MitreView";
import NetView from "./components/NetView";
import OTView from "./components/OTView";
import RuleModal from "./components/RuleModal";
import SettingsModal from "./components/SettingsModal";
import Sidebar from "./components/Sidebar";
import TagsModal from "./components/TagsModal";
import { useLiveTail, useVisibleInterval } from "./hooks";
import { parseRoute, pathFor } from "./routes";

// Seed for a rule pre-filled from an entry ("promote to detection").
export interface RuleSeed {
  name?: string;
  condition?: Cond;
  actions?: Action[];
}

const MAX_ROWS = 2000;
const OLDER_PAGE = 200;
// A reconnect backfill fetches at most this many missed rows (the server's
// page cap); a bigger gap falls back to a full reload.
const BACKFILL_PAGE = 1000;

// mergeEntries adds incoming rows to prev, skipping ids already present (the
// existing copy wins: it may carry a triage edit). The result stays in
// newest-first id order; cap trims the oldest rows. Returns prev unchanged
// when nothing new arrived, so React can skip the render.
function mergeEntries(prev: Entry[], incoming: Entry[], cap?: number): Entry[] {
  if (incoming.length === 0) return prev;
  const seen = new Set<number>();
  for (const e of prev) seen.add(e.id);
  const fresh: Entry[] = [];
  for (const e of incoming) {
    if (seen.has(e.id)) continue;
    seen.add(e.id);
    fresh.push(e);
  }
  if (fresh.length === 0) return prev;
  fresh.sort((a, b) => b.id - a.id);
  let out: Entry[];
  if (prev.length === 0 || fresh[fresh.length - 1].id > prev[0].id) {
    out = [...fresh, ...prev]; // the common case: everything new is newer
  } else if (fresh[0].id < prev[prev.length - 1].id) {
    out = [...prev, ...fresh]; // an older page
  } else {
    out = [...prev, ...fresh].sort((a, b) => b.id - a.id);
  }
  return cap !== undefined && out.length > cap ? out.slice(0, cap) : out;
}

const initialFilters: Filters = {
  q: "",
  host: "",
  app: "",
  severity: "",
  status: "",
  deviceClass: "",
  range: "60",
  sort: "time",
  desc: true,
};

type ModalState =
  | { kind: "none" }
  | { kind: "bucket"; bucket: Bucket | null }
  | { kind: "rule"; rule: Rule | null; seed?: RuleSeed }
  | { kind: "frameworkEditor"; framework: Framework | null }
  | { kind: "tags" }
  | { kind: "channels" }
  | { kind: "settings" };

// App gates the workspace behind a session: no user → login screen. The
// api layer fires "auth-expired" whenever a request comes back 401.
export default function App() {
  const [me, setMe] = useState<User | null | undefined>(undefined); // undefined = checking
  const [authInfo, setAuthInfo] = useState<AuthInfo | null>(null);
  // The session ended under us (expired, disabled, signed out elsewhere).
  const [expired, setExpired] = useState(false);

  useEffect(() => {
    fetchAuthInfo().then(setAuthInfo).catch(() => {});
    fetchMe().then(setMe).catch(() => setMe(null));
    const onExpired = () =>
      setMe((cur) => {
        if (cur) setExpired(true);
        return null;
      });
    window.addEventListener("auth-expired", onExpired);
    return () => window.removeEventListener("auth-expired", onExpired);
  }, []);

  if (me === undefined) return null;
  if (me === null) {
    return (
      <Login<User>
        tool="bucket"
        oidc={authInfo?.oidc.enabled ? { name: authInfo.oidc.name ?? "" } : null}
        notice={expired ? "Your session ended — sign in again." : undefined}
        onLogin={(u) => {
          setExpired(false);
          setMe(u);
        }}
      />
    );
  }
  return <Workspace me={me} onUserChanged={setMe} onSignOut={() => logout().finally(() => setMe(null))} />;
}

// IngestHealth is the small ingest-pipeline indicator in the page header.
function IngestHealth({ ingest }: { ingest: IngestStats }) {
  const fill = ingest.queue_capacity > 0 ? ingest.queue_depth / ingest.queue_capacity : 0;
  const detail =
    `Ingest queue ${ingest.queue_depth}/${ingest.queue_capacity} · inserted ${ingest.inserted.toLocaleString()}` +
    ` · failed attempts ${ingest.failed} · dropped ${ingest.dropped} · bad records ${ingest.bad_records}` +
    (ingest.retrying ? " · retrying a database error" : "");
  if (ingest.retrying) return <Badge tone="danger" title={detail}>ingest retrying</Badge>;
  if (ingest.dropped > 0) return <Badge tone="warning" title={detail}>{ingest.dropped.toLocaleString()} dropped</Badge>;
  if (fill >= 0.8) return <Badge tone="warning" title={detail}>ingest backlog {Math.round(fill * 100)}%</Badge>;
  return <Badge tone="success" title={detail}>ingest ok</Badge>;
}

const VIEW_ICON: Record<string, IconName> = {
  all: "description",
  bucket: "folder",
  tag: "sell",
  mitre: "crisis_alert",
  technique: "crisis_alert",
  ot: "factory",
  otalert: "factory",
  framework: "shield",
  frameworkitem: "shield",
  net: "lan",
};

function Workspace({
  me,
  onUserChanged,
  onSignOut,
}: {
  me: User;
  onUserChanged: (u: User) => void;
  onSignOut: () => void;
}) {
  const [filters, setFilters] = useState<Filters>(initialFilters);
  // The view comes from the URL hash (routes.ts), so it is deep-linkable
  // and back/forward work; selection/page are derived, stable per hash.
  const [path, navigate] = useHashRoute();
  const routeKey = path.join("/");
  // eslint-disable-next-line react-hooks/exhaustive-deps
  const route = useMemo(() => parseRoute(path), [routeKey]);
  useEffect(() => {
    if (!route) navigate(["logs"], { replace: true });
  }, [route, navigate]);
  const page = route && "page" in route ? route.page : null;
  const selection: Selection = useMemo(
    () => (route && "selection" in route ? route.selection : { kind: "all" }),
    [route],
  );
  const select = useCallback((sel: Selection) => navigate(pathFor(sel)), [navigate]);
  const [entries, setEntries] = useState<Entry[]>([]);
  const [selected, setSelected] = useState<Entry | null>(null);
  const [live, setLive] = useState(true);
  const [stats, setStats] = useState<Stats | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [buckets, setBuckets] = useState<Bucket[]>([]);
  const [frameworks, setFrameworks] = useState<Framework[]>([]);
  const [mitreCatalog, setMitreCatalog] = useState<MitreCatalog | null>(null);
  const [otCatalog, setOtCatalog] = useState<OTCatalog | null>(null);
  const [tags, setTags] = useState<Tag[]>([]);
  const [rules, setRules] = useState<Rule[]>([]);
  const [channels, setChannels] = useState<Channel[]>([]);
  const [modal, setModal] = useState<ModalState>({ kind: "none" });
  const [hints, setHints] = useState<Record<string, string>>({});
  const entriesRef = useRef<Entry[]>([]);
  entriesRef.current = entries;
  // Every full reload (filters/selection change) starts a new generation;
  // async results from an older generation are dropped.
  const genRef = useRef(0);
  // Whether this generation's first page has landed. Until then live
  // arrivals are held in pendingLive and merged into that page.
  const loadedRef = useRef(false);
  const pendingLive = useRef<Entry[]>([]);
  const frameRef = useRef<number | null>(null);
  // The socket (re)connected before the first page landed: backfill after.
  const backfillAfterLoad = useRef(false);
  const [reloadTick, setReloadTick] = useState(0);
  const olderBusy = useRef(false);
  const [olderLoading, setOlderLoading] = useState(false);
  // "Load older" hit the end: the oldest id at that moment. Derived rather
  // than a flag so trimming the list (live cap) re-enables the button.
  const [olderEndId, setOlderEndId] = useState<number | null>(null);

  const readOnly = me.role === "viewer";

  // A new view closes the entry detail.
  useEffect(() => setSelected(null), [routeKey]);

  useEffect(() => {
    fetchHints().then(setHints).catch(() => {});
  }, []);

  const tagsById = useMemo(() => new Map(tags.map((t) => [t.id, t])), [tags]);

  const reloadMeta = useCallback(async () => {
    try {
      const [b, t, r, ch] = await Promise.all([fetchBuckets(), fetchTags(), fetchRules(), fetchChannels()]);
      setBuckets(b);
      setTags(t);
      setRules(r);
      setChannels(ch);
    } catch (e) {
      setError(String(e));
    }
  }, []);

  useEffect(() => {
    void reloadMeta();
  }, [reloadMeta]);

  const reloadFrameworks = useCallback(() => {
    fetchFrameworks().then(setFrameworks).catch(() => {});
  }, []);

  // Frameworks include site-defined ones, so reload after edits. The MITRE/OT
  // catalogs (used by hand-classification pickers) are static.
  useEffect(() => {
    reloadFrameworks();
    fetchMitre().then(setMitreCatalog).catch(() => {});
    fetchOt().then(setOtCatalog).catch(() => {});
  }, [reloadFrameworks]);

  // The matrix views (ATT&CK / OT) render their own data; the entry list and
  // live tail pause while one is open.
  const isMatrix =
    selection.kind === "mitre" || selection.kind === "ot" || selection.kind === "framework" || selection.kind === "net";
  // List pages (buckets, rules, frameworks) show no entries either.
  const listPaused = isMatrix || page !== null;
  // A column sort returns one ranked page; time sort streams + paginates.
  const pageLimit = filters.sort === "time" ? 200 : 1000;

  // Backfill rows that arrived while the live socket was down (or before it
  // first opened). Uses time order with after_id regardless of the column
  // sort, since only that mode supports it; a gap wider than one page means
  // the list is too far behind, so reload it instead.
  const backfill = useCallback(async () => {
    const gen = genRef.current;
    const known = [...pendingLive.current, ...entriesRef.current];
    const newest = known.reduce((m, e) => Math.max(m, e.id), 0);
    const timeFilters: Filters = { ...filters, sort: "time", desc: true };
    try {
      const rows =
        newest > 0
          ? await fetchEntries(timeFilters, selection, { afterId: newest, limit: BACKFILL_PAGE })
          : await fetchEntries(timeFilters, selection, { limit: OLDER_PAGE });
      if (gen !== genRef.current) return;
      if (newest > 0 && rows.length >= BACKFILL_PAGE) {
        setReloadTick((t) => t + 1);
        return;
      }
      setEntries((prev) => mergeEntries(prev, rows, MAX_ROWS));
    } catch {
      // Best effort: the socket is up again and the next reload catches up.
    }
  }, [filters, selection]);
  const backfillRef = useRef(backfill);
  backfillRef.current = backfill;

  // Full reload when filters or the selected bucket/tag/technique change.
  useEffect(() => {
    if (listPaused) return;
    const gen = ++genRef.current;
    loadedRef.current = false;
    pendingLive.current = [];
    backfillAfterLoad.current = false;
    if (frameRef.current !== null) {
      cancelAnimationFrame(frameRef.current);
      frameRef.current = null;
    }
    olderBusy.current = false;
    setOlderLoading(false);
    setOlderEndId(null);
    fetchEntries(filters, selection, { limit: pageLimit })
      .then((rows) => {
        if (gen !== genRef.current) return;
        // Merge (not replace) so live arrivals that beat this response stay.
        const buffered = pendingLive.current;
        pendingLive.current = [];
        loadedRef.current = true;
        const merged = mergeEntries(mergeEntries([], rows), buffered, MAX_ROWS);
        setEntries(merged);
        if (filters.sort === "time" && rows.length < pageLimit && merged.length > 0) {
          setOlderEndId(merged[merged.length - 1].id);
        }
        setError(null);
        if (backfillAfterLoad.current) {
          backfillAfterLoad.current = false;
          void backfillRef.current();
        }
      })
      .catch((e) => gen === genRef.current && setError(String(e)));
  }, [filters, selection, listPaused, pageLimit, reloadTick]);

  // Display order is computed client-side so live arrivals slot into the
  // chosen sort without a refetch (the server still decides which rows the
  // page contains). entries is kept newest-first, so time order is free.
  const sortedEntries = useMemo(() => {
    if (filters.sort === "time") return filters.desc ? entries : [...entries].reverse();
    const dir = filters.desc ? -1 : 1;
    const tiebreak = (a: Entry, b: Entry) => b.id - a.id;
    const arr = [...entries];
    arr.sort((a, b) => {
      switch (filters.sort) {
        case "severity":
          return (a.severity - b.severity) * dir || tiebreak(a, b);
        case "priority":
          return (a.priority - b.priority) * dir || tiebreak(a, b);
        case "host":
          return a.host.localeCompare(b.host) * dir || tiebreak(a, b);
        case "app":
          return a.app_name.localeCompare(b.app_name) * dir || tiebreak(a, b);
        case "device_class":
          return a.device_class.localeCompare(b.device_class) * dir || tiebreak(a, b);
        default:
          return (a.id - b.id) * dir;
      }
    });
    return arr;
  }, [entries, filters.sort, filters.desc]);

  // Clicking a column header sorts by it; clicking the active column flips
  // the direction.
  const onSort = (key: SortKey) =>
    setFilters((f) => (f.sort === key ? { ...f, desc: !f.desc } : { ...f, sort: key, desc: true }));

  const onSelectTechnique = (id: string) => select({ kind: "technique", id });
  const onSelectAlert = (id: string) => select({ kind: "otalert", id });
  const onSelectFrameworkItem = (fw: string, id: string) => select({ kind: "frameworkitem", fw, id });

  // Live tail: the server pushes entries matching the same condition the
  // list query uses. Arrivals are batched per animation frame (one merge and
  // one re-sort per frame, not per message) and deduped by id.
  const wsURL = useMemo(
    () => (live && !listPaused ? liveTailURL(filters, selection) : null),
    [live, filters, selection, listPaused],
  );
  const flushLive = useCallback(() => {
    frameRef.current = null;
    if (!loadedRef.current) return;
    const batch = pendingLive.current;
    pendingLive.current = [];
    setEntries((prev) => mergeEntries(prev, batch, MAX_ROWS));
  }, []);
  const wsOpen = useLiveTail(
    wsURL,
    useCallback(
      (e: Entry) => {
        const buf = pendingLive.current;
        buf.push(e);
        // Frames don't run in a hidden tab; don't let the buffer grow forever.
        if (buf.length > MAX_ROWS * 2) pendingLive.current = buf.slice(-MAX_ROWS);
        if (loadedRef.current && frameRef.current === null) {
          frameRef.current = requestAnimationFrame(flushLive);
        }
      },
      [flushLive],
    ),
    useCallback(() => {
      if (loadedRef.current) void backfillRef.current();
      else backfillAfterLoad.current = true;
    }, []),
    // The socket dropped: before reconnecting, check the session is still
    // good. A disabled/expired account goes back to sign-in instead of
    // reconnect-looping; a role change (demotion) is picked up in place.
    useCallback(async () => {
      try {
        const u = await fetchMe();
        if (u.role !== me.role || u.disabled) onUserChanged(u);
        return true;
      } catch (e) {
        if (e instanceof ApiError && e.status === 401) {
          window.dispatchEvent(new Event("auth-expired"));
          return false;
        }
        return true; // network blip: keep retrying with backoff
      }
    }, [me.role, onUserChanged]),
  );

  useVisibleInterval(() => {
    fetchStats().then(setStats).catch(() => {});
  }, 10_000);

  const loadOlder = async () => {
    const current = entriesRef.current;
    if (current.length === 0 || olderBusy.current) return;
    const gen = genRef.current;
    const oldest = current[current.length - 1].id; // entries are newest-first
    olderBusy.current = true;
    setOlderLoading(true);
    try {
      const older = await fetchEntries(filters, selection, { beforeId: oldest, limit: OLDER_PAGE });
      if (gen !== genRef.current) return; // the query changed meanwhile
      const merged = mergeEntries(entriesRef.current, older);
      setEntries((prev) => mergeEntries(prev, older));
      if (older.length < OLDER_PAGE && merged.length > 0) setOlderEndId(merged[merged.length - 1].id);
    } catch (e) {
      if (gen === genRef.current) setError(String(e));
    } finally {
      if (gen === genRef.current) {
        olderBusy.current = false;
        setOlderLoading(false);
      }
    }
  };
  const olderState: "idle" | "loading" | "end" = olderLoading
    ? "loading"
    : olderEndId !== null && entries.length > 0 && entries[entries.length - 1].id === olderEndId
      ? "end"
      : "idle";

  // Reflect a triage change (status/priority/tags) in the list and the
  // detail pane without a refetch.
  const onEntryUpdated = (e: Entry) => {
    setEntries((prev) => prev.map((p) => (p.id === e.id ? e : p)));
    setSelected((sel) => (sel?.id === e.id ? e : sel));
  };

  const closeModal = (changed: boolean) => {
    setModal({ kind: "none" });
    if (changed) {
      void reloadMeta();
      reloadFrameworks();
      // A rule/bucket change can reshape the current view.
      setFilters((f) => ({ ...f }));
    }
  };

  // "Create rule from this entry": seed a condition that matches similar
  // entries (same app), plus actions to re-stamp any hand-added classification.
  const createRuleFromEntry = (entry: Entry) => {
    const actions: Action[] = [];
    if ((entry.mitre ?? []).length > 0) actions.push({ type: "set_mitre", mitre: entry.mitre });
    if ((entry.ot ?? []).length > 0) actions.push({ type: "set_ot", ot: entry.ot });
    const condition: Cond =
      entry.app_name !== ""
        ? { all: [{ field: "app_name", op: "eq", value: entry.app_name }] }
        : { field: "host", op: "eq", value: entry.host };
    setModal({
      kind: "rule",
      rule: null,
      seed: { name: entry.app_name ? `Classify ${entry.app_name}` : "Classify entries", condition, actions },
    });
  };

  const viewTitle =
    selection.kind === "all"
      ? "All Logs"
      : selection.kind === "bucket"
        ? (buckets.find((b) => b.id === selection.id)?.name ?? "Bucket")
        : selection.kind === "mitre"
          ? "ATT&CK matrix"
          : selection.kind === "technique"
            ? `ATT&CK ${selection.id}`
            : selection.kind === "ot"
              ? "ICS/OT Alerts"
              : selection.kind === "otalert"
                ? `OT ${selection.id}`
                : selection.kind === "framework"
                  ? (frameworks.find((f) => f.id === selection.fw)?.name ?? "Framework")
                  : selection.kind === "frameworkitem"
                    ? `${frameworks.find((f) => f.id === selection.fw)?.short ?? "Framework"} · ${selection.id}`
                    : selection.kind === "net"
                      ? "Network security"
                      : `Tag: ${tagsById.get(selection.id)?.name ?? selection.id}`;
  const title =
    page === "buckets" ? "Buckets" : page === "rules" ? "Rules" : page === "frameworks" ? "Frameworks" : viewTitle;

  const statsMeta = stats && (
    <>
      <span>
        ~{stats.approx_total.toLocaleString()} entries · {stats.last_minute}/min
      </span>
      {stats.ingest && <IngestHealth ingest={stats.ingest} />}
    </>
  );

  return (
    <AppShell
      tool="bucket"
      links={hints}
      section={route?.section ?? "logs"}
      title={title}
      user={me}
      onSignOut={onSignOut}
      usersDeleteNote="Their buckets become ownerless yard buckets."
      accountItems={
        me.role === "admin"
          ? [{ id: "settings", label: "Settings…", icon: "tune", onSelect: () => setModal({ kind: "settings" }) }]
          : []
      }
      navContent={
        <Sidebar
          buckets={buckets}
          tags={tags}
          rules={rules}
          channels={channels}
          frameworks={frameworks}
          selection={page ? null : selection}
          page={page}
          me={me}
          readOnly={readOnly}
          onEditBucket={(bucket) => setModal({ kind: "bucket", bucket })}
          onEditRule={(rule) => setModal({ kind: "rule", rule })}
          onEditFramework={(framework) => setModal({ kind: "frameworkEditor", framework })}
          onManageTags={() => setModal({ kind: "tags" })}
          onManageChannels={() => setModal({ kind: "channels" })}
        />
      }
    >
      {page === "buckets" ? (
        <BucketsPage buckets={buckets} me={me} readOnly={readOnly} onEdit={(bucket) => setModal({ kind: "bucket", bucket })} />
      ) : page === "rules" ? (
        <RulesPage rules={rules} tagsById={tagsById} readOnly={readOnly} onEdit={(rule) => setModal({ kind: "rule", rule })} />
      ) : page === "frameworks" ? (
        <FrameworksPage
          frameworks={frameworks}
          isAdmin={me.role === "admin"}
          onEdit={(framework) => setModal({ kind: "frameworkEditor", framework })}
        />
      ) : (
        <>
          <PageHeader
            title={viewTitle}
            icon={VIEW_ICON[selection.kind]}
            meta={statsMeta}
            actions={
              !isMatrix && (
                <Button
                  className={live && wsOpen ? "live on" : "live"}
                  icon={live ? "sensors" : "pause"}
                  aria-pressed={live}
                  title={live ? "Pause the live tail" : "Resume the live tail"}
                  onClick={() => setLive(!live)}
                >
                  {live ? (wsOpen ? "Live" : "Connecting…") : "Paused"}
                </Button>
              )
            }
          />
          <FilterBar filters={filters} onChange={setFilters} />
          {error && (
            <Banner className="page-banner" onDismiss={() => setError(null)}>
              {error}
            </Banner>
          )}
          <div className="content">
            {selection.kind === "net" ? (
              <NetView filters={filters} me={me} />
            ) : selection.kind === "ot" ? (
              <OTView filters={filters} selection={selection} onSelectAlert={onSelectAlert} />
            ) : selection.kind === "framework" ? (
              (() => {
                const fw = frameworks.find((f) => f.id === selection.fw);
                return fw ? (
                  <FrameworkView
                    framework={fw}
                    filters={filters}
                    selection={selection}
                    onSelectItem={onSelectFrameworkItem}
                  />
                ) : (
                  <Loading label="Loading framework…" />
                );
              })()
            ) : isMatrix ? (
              <MitreView filters={filters} selection={selection} onSelectTechnique={onSelectTechnique} />
            ) : (
              <>
                <LogTable
                  entries={sortedEntries}
                  tagsById={tagsById}
                  selectedId={selected?.id ?? null}
                  sort={filters.sort}
                  desc={filters.desc}
                  onSort={onSort}
                  onSelect={setSelected}
                  onDeselect={() => setSelected(null)}
                  onSelectTechnique={onSelectTechnique}
                  olderState={olderState}
                  onLoadOlder={() => void loadOlder()}
                />
                {selected && (
                  <EntryDetail
                    key={selected.id}
                    entry={selected}
                    tags={tags}
                    tagsById={tagsById}
                    mitreCatalog={mitreCatalog}
                    otCatalog={otCatalog}
                    readOnly={readOnly}
                    onClose={() => {
                      const id = selected.id;
                      setSelected(null);
                      // Back to the row the detail came from.
                      document.querySelector<HTMLElement>(`.logtable tr[data-id="${id}"]`)?.focus();
                    }}
                    onUpdated={onEntryUpdated}
                    onCreateRule={createRuleFromEntry}
                  />
                )}
              </>
            )}
          </div>
        </>
      )}

      {modal.kind === "bucket" && <BucketModal bucket={modal.bucket} tags={tags} me={me} onClose={closeModal} />}
      {modal.kind === "rule" && (
        <RuleModal
          rule={modal.rule}
          seed={modal.seed}
          tags={tags}
          channels={channels}
          mitreCatalog={mitreCatalog}
          otCatalog={otCatalog}
          onClose={closeModal}
        />
      )}
      {modal.kind === "frameworkEditor" && (
        <FrameworkEditor
          framework={modal.framework}
          mitreCatalog={mitreCatalog}
          otCatalog={otCatalog}
          onClose={closeModal}
        />
      )}
      {modal.kind === "tags" && <TagsModal tags={tags} onClose={closeModal} />}
      {modal.kind === "channels" && <ChannelsModal channels={channels} onClose={closeModal} />}
      {modal.kind === "settings" && <SettingsModal onClose={() => closeModal(false)} />}
    </AppShell>
  );
}
