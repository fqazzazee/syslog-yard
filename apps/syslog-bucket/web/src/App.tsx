import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  fetchAuthInfo,
  fetchBuckets,
  fetchChannels,
  fetchEntries,
  fetchHints,
  fetchMe,
  fetchRules,
  fetchStats,
  fetchTags,
  liveTailURL,
  logout,
} from "./api";
import type { AuthInfo, Bucket, Channel, Entry, Filters, Rule, Selection, SortKey, Stats, Tag, User } from "./types";
import { About } from "./components/About";
import AccountModal from "./components/AccountModal";
import BucketModal from "./components/BucketModal";
import ChannelsModal from "./components/ChannelsModal";
import EntryDetail from "./components/EntryDetail";
import { Icon } from "./components/Icon";
import FilterBar from "./components/FilterBar";
import Login from "./components/Login";
import LogTable from "./components/LogTable";
import MitreView from "./components/MitreView";
import OTView from "./components/OTView";
import RuleModal from "./components/RuleModal";
import Sidebar from "./components/Sidebar";
import TagsModal from "./components/TagsModal";
import UsersModal from "./components/UsersModal";
import { YardNav } from "./components/YardNav";
import { useLiveTail } from "./hooks";

const MAX_ROWS = 2000;

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
  | { kind: "rule"; rule: Rule | null }
  | { kind: "tags" }
  | { kind: "channels" }
  | { kind: "users" }
  | { kind: "account" };

// App gates the workspace behind a session: no user → login screen. The
// api layer fires "auth-expired" whenever a request comes back 401.
export default function App() {
  const [me, setMe] = useState<User | null | undefined>(undefined); // undefined = checking
  const [authInfo, setAuthInfo] = useState<AuthInfo | null>(null);

  useEffect(() => {
    fetchAuthInfo().then(setAuthInfo).catch(() => {});
    fetchMe().then(setMe).catch(() => setMe(null));
    const expired = () => setMe(null);
    window.addEventListener("auth-expired", expired);
    return () => window.removeEventListener("auth-expired", expired);
  }, []);

  if (me === undefined) return null;
  if (me === null) return <Login info={authInfo} onLogin={setMe} />;
  return <Workspace me={me} onSignOut={() => logout().finally(() => setMe(null))} />;
}

function Workspace({ me, onSignOut }: { me: User; onSignOut: () => void }) {
  const [filters, setFilters] = useState<Filters>(initialFilters);
  const [selection, setSelection] = useState<Selection>({ kind: "all" });
  const [entries, setEntries] = useState<Entry[]>([]);
  const [selected, setSelected] = useState<Entry | null>(null);
  const [live, setLive] = useState(true);
  const [stats, setStats] = useState<Stats | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [buckets, setBuckets] = useState<Bucket[]>([]);
  const [tags, setTags] = useState<Tag[]>([]);
  const [rules, setRules] = useState<Rule[]>([]);
  const [channels, setChannels] = useState<Channel[]>([]);
  const [modal, setModal] = useState<ModalState>({ kind: "none" });
  const [hints, setHints] = useState<Record<string, string>>({});
  const [menuOpen, setMenuOpen] = useState(false);
  const [aboutOpen, setAboutOpen] = useState(false);
  const menuRef = useRef<HTMLDivElement>(null);
  const entriesRef = useRef<Entry[]>([]);
  entriesRef.current = entries;

  const readOnly = me.role === "viewer";

  // The account menu closes like a menu should: outside click or Escape.
  useEffect(() => {
    if (!menuOpen) return;
    const onDown = (e: MouseEvent) => {
      if (!menuRef.current?.contains(e.target as Node)) setMenuOpen(false);
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setMenuOpen(false);
    };
    document.addEventListener("mousedown", onDown);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onDown);
      document.removeEventListener("keydown", onKey);
    };
  }, [menuOpen]);

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

  // The matrix views (ATT&CK / OT) render their own data; the entry list and
  // live tail pause while one is open.
  const isMatrix = selection.kind === "mitre" || selection.kind === "ot";
  // A column sort returns one ranked page; time sort streams + paginates.
  const pageLimit = filters.sort === "time" ? 200 : 1000;

  // Full reload when filters or the selected bucket/tag/technique change.
  useEffect(() => {
    if (isMatrix) return;
    let stale = false;
    fetchEntries(filters, selection, { limit: pageLimit })
      .then((rows) => {
        if (stale) return;
        setEntries(rows);
        setError(null);
      })
      .catch((e) => !stale && setError(String(e)));
    return () => {
      stale = true;
    };
  }, [filters, selection, isMatrix, pageLimit]);

  // Display order is computed client-side so live arrivals slot into the
  // chosen sort without a refetch (the server still decides which rows the
  // page contains).
  const sortedEntries = useMemo(() => {
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

  const onSelectTechnique = (id: string) => {
    setSelection({ kind: "technique", id });
    setSelected(null);
  };

  const onSelectAlert = (id: string) => {
    setSelection({ kind: "otalert", id });
    setSelected(null);
  };

  // Live tail: the server pushes entries matching the same condition the
  // list query uses; prepend them as they arrive.
  const wsURL = useMemo(
    () => (live && !isMatrix ? liveTailURL(filters, selection) : null),
    [live, filters, selection, isMatrix],
  );
  const wsOpen = useLiveTail(
    wsURL,
    useCallback((e: Entry) => {
      setEntries((prev) => (prev.some((p) => p.id === e.id) ? prev : [e, ...prev].slice(0, MAX_ROWS)));
    }, []),
  );

  useEffect(() => {
    const refresh = () => fetchStats().then(setStats).catch(() => {});
    refresh();
    const id = setInterval(refresh, 10_000);
    return () => clearInterval(id);
  }, []);

  const loadOlder = async () => {
    const current = entriesRef.current;
    if (current.length === 0) return;
    const oldest = current[current.length - 1].id;
    try {
      const older = await fetchEntries(filters, selection, { beforeId: oldest });
      setEntries((prev) => [...prev, ...older]);
    } catch (e) {
      setError(String(e));
    }
  };

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
      // A rule/bucket change can reshape the current view.
      setFilters((f) => ({ ...f }));
    }
  };

  const title =
    selection.kind === "all"
      ? "All Logs"
      : selection.kind === "bucket"
        ? (buckets.find((b) => b.id === selection.id)?.name ?? "Bucket")
        : selection.kind === "mitre"
          ? "ATT&CK matrix"
          : selection.kind === "technique"
            ? `ATT&CK ${selection.id}`
            : selection.kind === "ot"
              ? "OT alerts"
              : selection.kind === "otalert"
                ? `OT ${selection.id}`
                : `Tag: ${tagsById.get(selection.id)?.name ?? selection.id}`;

  return (
    <div className="app">
      <header className="topbar">
        <h1 className="brand">
          <span className="logo">
            <Icon name="inbox" size={22} />
          </span>{" "}
          syslog-bucket <span className="bucket-label">{title}</span>
        </h1>
        <YardNav links={hints} current="bucket" />
        {stats && (
          <span className="stats">
            ~{stats.approx_total.toLocaleString()} entries · {stats.last_minute}/min
          </span>
        )}
        <div className="spacer" />
        {!isMatrix && (
          <button className={live && wsOpen ? "live on" : "live"} onClick={() => setLive(!live)}>
            <Icon name={live ? "sensors" : "pause"} size={15} />{" "}
            {live ? (wsOpen ? "Live" : "Connecting…") : "Paused"}
          </button>
        )}
        <button className="help-btn" title="About & help" onClick={() => setAboutOpen(true)}>
          <Icon name="help" size={18} />
        </button>
        <div className="user-menu" ref={menuRef}>
          <button
            className={`user-btn${menuOpen ? " open" : ""}`}
            title="Account menu"
            onClick={() => setMenuOpen(!menuOpen)}
          >
            <Icon name="account_circle" size={16} /> {me.display_name || me.username}{" "}
            <span className={`role-badge role-${me.role}`}>{me.role}</span>
            <Icon name="keyboard_arrow_down" size={16} className="caret" />
          </button>
          {menuOpen && (
            <div className="user-dropdown" onClick={() => setMenuOpen(false)}>
              {me.role === "admin" && (
                <button onClick={() => setModal({ kind: "users" })}>
                  <Icon name="manage_accounts" size={16} /> Users…
                </button>
              )}
              <button onClick={() => setModal({ kind: "account" })}>
                <Icon name="account_circle" size={16} /> Account…
              </button>
              <button onClick={onSignOut}>
                <Icon name="logout" size={16} /> Sign out
              </button>
            </div>
          )}
        </div>
      </header>
      {aboutOpen && <About tool="bucket" onClose={() => setAboutOpen(false)} />}

      <div className="body">
        <Sidebar
          buckets={buckets}
          tags={tags}
          rules={rules}
          channels={channels}
          selection={selection}
          me={me}
          readOnly={readOnly}
          onSelect={(sel) => {
            setSelection(sel);
            setSelected(null);
          }}
          onEditBucket={(bucket) => setModal({ kind: "bucket", bucket })}
          onEditRule={(rule) => setModal({ kind: "rule", rule })}
          onManageTags={() => setModal({ kind: "tags" })}
          onManageChannels={() => setModal({ kind: "channels" })}
        />

        <div className="main-pane">
          <FilterBar filters={filters} onChange={setFilters} />
          {error && <div className="error">{error}</div>}
          <main className="content">
            {selection.kind === "ot" ? (
              <OTView filters={filters} selection={selection} onSelectAlert={onSelectAlert} />
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
                  onSelectTechnique={onSelectTechnique}
                  onLoadOlder={() => void loadOlder()}
                />
                {selected && (
                  <EntryDetail
                    entry={selected}
                    tags={tags}
                    tagsById={tagsById}
                    readOnly={readOnly}
                    onClose={() => setSelected(null)}
                    onUpdated={onEntryUpdated}
                  />
                )}
              </>
            )}
          </main>
        </div>
      </div>

      {modal.kind === "bucket" && <BucketModal bucket={modal.bucket} tags={tags} me={me} onClose={closeModal} />}
      {modal.kind === "rule" && <RuleModal rule={modal.rule} tags={tags} channels={channels} onClose={closeModal} />}
      {modal.kind === "tags" && <TagsModal tags={tags} onClose={closeModal} />}
      {modal.kind === "channels" && <ChannelsModal channels={channels} onClose={closeModal} />}
      {modal.kind === "users" && <UsersModal me={me} onClose={() => closeModal(false)} />}
      {modal.kind === "account" && <AccountModal me={me} onClose={() => closeModal(false)} />}
    </div>
  );
}
