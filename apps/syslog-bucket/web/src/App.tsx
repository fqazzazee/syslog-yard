import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  fetchAuthInfo,
  fetchBuckets,
  fetchEntries,
  fetchHints,
  fetchMe,
  fetchRules,
  fetchStats,
  fetchTags,
  liveTailURL,
  logout,
} from "./api";
import type { AuthInfo, Bucket, Entry, Filters, Rule, Selection, Stats, Tag, User } from "./types";
import AccountModal from "./components/AccountModal";
import BucketModal from "./components/BucketModal";
import EntryDetail from "./components/EntryDetail";
import FilterBar from "./components/FilterBar";
import Login from "./components/Login";
import LogTable from "./components/LogTable";
import RuleModal from "./components/RuleModal";
import Sidebar from "./components/Sidebar";
import TagsModal from "./components/TagsModal";
import UsersModal from "./components/UsersModal";
import { YardNav } from "./components/YardNav";
import { useLiveTail } from "./hooks";

const MAX_ROWS = 2000;

const initialFilters: Filters = { q: "", host: "", app: "", severity: "", status: "", range: "60" };

type ModalState =
  | { kind: "none" }
  | { kind: "bucket"; bucket: Bucket | null }
  | { kind: "rule"; rule: Rule | null }
  | { kind: "tags" }
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
  const [modal, setModal] = useState<ModalState>({ kind: "none" });
  const [hints, setHints] = useState<Record<string, string>>({});
  const [menuOpen, setMenuOpen] = useState(false);
  const entriesRef = useRef<Entry[]>([]);
  entriesRef.current = entries;

  const readOnly = me.role === "viewer";

  useEffect(() => {
    fetchHints().then(setHints).catch(() => {});
  }, []);

  const tagsById = useMemo(() => new Map(tags.map((t) => [t.id, t])), [tags]);

  const reloadMeta = useCallback(async () => {
    try {
      const [b, t, r] = await Promise.all([fetchBuckets(), fetchTags(), fetchRules()]);
      setBuckets(b);
      setTags(t);
      setRules(r);
    } catch (e) {
      setError(String(e));
    }
  }, []);

  useEffect(() => {
    void reloadMeta();
  }, [reloadMeta]);

  // Full reload when filters or the selected bucket/tag change.
  useEffect(() => {
    let stale = false;
    fetchEntries(filters, selection)
      .then((rows) => {
        if (stale) return;
        setEntries(rows);
        setError(null);
      })
      .catch((e) => !stale && setError(String(e)));
    return () => {
      stale = true;
    };
  }, [filters, selection]);

  // Live tail: the server pushes entries matching the same condition the
  // list query uses; prepend them as they arrive.
  const wsURL = useMemo(() => (live ? liveTailURL(filters, selection) : null), [live, filters, selection]);
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
        : `Tag: ${tagsById.get(selection.id)?.name ?? selection.id}`;

  return (
    <div className="app">
      <header className="topbar">
        <h1>
          syslog-bucket <span className="bucket-label">{title}</span>
        </h1>
        <YardNav links={hints} current="bucket" />
        {stats && (
          <span className="stats">
            ~{stats.approx_total.toLocaleString()} entries · {stats.last_minute}/min
          </span>
        )}
        <div className="user-menu">
          <button className="user-btn" onClick={() => setMenuOpen(!menuOpen)}>
            👤 {me.display_name || me.username} <span className={`role-badge role-${me.role}`}>{me.role}</span>
          </button>
          {menuOpen && (
            <div className="user-dropdown" onClick={() => setMenuOpen(false)}>
              {me.role === "admin" && <button onClick={() => setModal({ kind: "users" })}>Users…</button>}
              <button onClick={() => setModal({ kind: "account" })}>Account…</button>
              <button onClick={onSignOut}>Sign out</button>
            </div>
          )}
        </div>
        <button className={live && wsOpen ? "live on" : "live"} onClick={() => setLive(!live)}>
          {live ? (wsOpen ? "● Live" : "● Connecting…") : "‖ Paused"}
        </button>
      </header>

      <div className="body">
        <Sidebar
          buckets={buckets}
          tags={tags}
          rules={rules}
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
        />

        <div className="main-pane">
          <FilterBar filters={filters} onChange={setFilters} />
          {error && <div className="error">{error}</div>}
          <main className="content">
            <LogTable
              entries={entries}
              tagsById={tagsById}
              selectedId={selected?.id ?? null}
              onSelect={setSelected}
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
          </main>
        </div>
      </div>

      {modal.kind === "bucket" && <BucketModal bucket={modal.bucket} tags={tags} me={me} onClose={closeModal} />}
      {modal.kind === "rule" && <RuleModal rule={modal.rule} tags={tags} onClose={closeModal} />}
      {modal.kind === "tags" && <TagsModal tags={tags} onClose={closeModal} />}
      {modal.kind === "users" && <UsersModal me={me} onClose={() => closeModal(false)} />}
      {modal.kind === "account" && <AccountModal me={me} onClose={() => closeModal(false)} />}
    </div>
  );
}
