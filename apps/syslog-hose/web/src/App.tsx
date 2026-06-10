import { useEffect, useRef, useState } from "react";
import { api, AuthUser, Job, PresetSummary, TailEvent } from "./api";
import { JobForm } from "./JobForm";
import { Login } from "./Login";
import { PresetsView } from "./PresetsView";
import { Tail } from "./Tail";
import { YardNav } from "./YardNav";

type TabName = "jobs" | "presets";

type AuthState = { enabled: boolean; user: AuthUser | null };

// App gates the workspace behind yard auth when the deployment enables it
// (YARD_AUTH_URL); standalone runs stay open.
export default function App() {
  const [auth, setAuth] = useState<AuthState | undefined>(undefined);

  useEffect(() => {
    api
      .authInfo()
      .then(async (info) => {
        if (!info.enabled) return setAuth({ enabled: false, user: null });
        try {
          setAuth({ enabled: true, user: await api.me() });
        } catch {
          setAuth({ enabled: true, user: null });
        }
      })
      .catch(() => setAuth({ enabled: false, user: null }));
    const expired = () => setAuth((a) => (a?.enabled ? { enabled: true, user: null } : a));
    window.addEventListener("auth-expired", expired);
    return () => window.removeEventListener("auth-expired", expired);
  }, []);

  if (auth === undefined) return null;
  if (auth.enabled && !auth.user) {
    return <Login onLogin={(user) => setAuth({ enabled: true, user })} />;
  }
  return (
    <Workspace
      user={auth.user}
      onSignOut={() => api.logout().finally(() => setAuth({ enabled: true, user: null }))}
    />
  );
}

function Workspace({ user, onSignOut }: { user: AuthUser | null; onSignOut: () => void }) {
  const [tab, setTab] = useState<TabName>("jobs");
  const [jobs, setJobs] = useState<Job[]>([]);
  const [presets, setPresets] = useState<PresetSummary[]>([]);
  const [events, setEvents] = useState<TailEvent[]>([]);
  const [editing, setEditing] = useState<Partial<Job> | null>(null);
  const [error, setError] = useState("");
  const [showTail, setShowTail] = useState(true);
  const [hints, setHints] = useState<Record<string, string>>({});
  const paused = useRef(false);
  const readOnly = user?.role === "viewer";

  const refreshPresets = () => api.presets().then(setPresets).catch(() => {});

  useEffect(() => {
    refreshPresets();
    api.hints().then(setHints).catch(() => {});
    const es = new EventSource("/api/stream");
    es.onmessage = (m) => {
      const data = JSON.parse(m.data) as { jobs: Job[]; events: TailEvent[] };
      setJobs(data.jobs ?? []);
      if (!paused.current && data.events?.length) {
        setEvents((prev) => [...prev, ...data.events].slice(-300));
      }
    };
    es.onerror = () => {
      /* EventSource auto-reconnects */
    };
    return () => es.close();
  }, []);

  const act = (fn: () => Promise<unknown>) => {
    setError("");
    fn()
      .then(() => api.jobs().then(setJobs))
      .catch((e: Error) => setError(e.message));
  };

  const running = jobs.filter((j) => j.running).length;

  // New jobs start aimed at the suite neighbor when the deployment
  // suggests one (HOSE_SUGGESTED_DEST, e.g. "syslog-valve:514").
  const newJob = (): Partial<Job> => {
    const dest = hints.suggestedDest;
    if (!dest) return {};
    const i = dest.lastIndexOf(":");
    if (i < 1) return { host: dest };
    return { host: dest.slice(0, i), port: Number(dest.slice(i + 1)) || 514 };
  };

  return (
    <div className="app">
      <header>
        <h1>
          <span className="logo">⟫⟫</span> syslog-hose
        </h1>
        <span className="sub">syslog generator</span>
        <YardNav links={hints} current="hose" />
        <nav>
          <button className={tab === "jobs" ? "tab active" : "tab"} onClick={() => setTab("jobs")}>
            Jobs {running > 0 && <span className="badge">{running} running</span>}
          </button>
          <button
            className={tab === "presets" ? "tab active" : "tab"}
            onClick={() => setTab("presets")}
          >
            Presets
          </button>
        </nav>
        <div className="spacer" />
        {running > 0 && !readOnly && (
          <button className="danger" onClick={() => act(api.stopAll)}>
            ■ Stop all
          </button>
        )}
        {user && (
          <span className="user-chip">
            👤 {user.display_name || user.username}
            <span className="role-tag">{user.role}</span>
            <button className="quiet" onClick={onSignOut}>
              Sign out
            </button>
          </span>
        )}
      </header>

      {error && (
        <div className="error-bar" onClick={() => setError("")}>
          {error} ✕
        </div>
      )}

      {tab === "jobs" && (
        <main>
          {!readOnly && (
            <div className="toolbar">
              <button className="primary" onClick={() => setEditing(newJob())}>
                + New job
              </button>
            </div>
          )}
          {jobs.length === 0 && (
            <div className="empty">
              No jobs yet. Create one to start spraying syslog at something.
            </div>
          )}
          <div className="cards">
            {jobs.map((j) => (
              <JobCard
                key={j.id}
                job={j}
                readOnly={readOnly}
                onStart={() => act(() => api.startJob(j.id))}
                onStop={() => act(() => api.stopJob(j.id))}
                onEdit={() => setEditing(j)}
                onDuplicate={() =>
                  setEditing({ ...j, id: undefined, name: `${j.name} (copy)` } as Partial<Job>)
                }
                onDelete={() => {
                  if (confirm(`Delete job "${j.name}"?`)) act(() => api.deleteJob(j.id));
                }}
              />
            ))}
          </div>
        </main>
      )}

      {tab === "presets" && (
        <main>
          <PresetsView presets={presets} onChanged={refreshPresets} />
        </main>
      )}

      {editing !== null && (
        <JobForm
          initial={editing}
          presets={presets}
          onClose={() => setEditing(null)}
          onSaved={() => {
            setEditing(null);
            api.jobs().then(setJobs);
          }}
        />
      )}

      <Tail
        events={events}
        jobs={jobs}
        visible={showTail}
        onToggle={() => setShowTail(!showTail)}
        onPause={(p) => (paused.current = p)}
        onClear={() => setEvents([])}
      />
    </div>
  );
}

function fmtCount(n: number): string {
  if (n >= 1_000_000) return (n / 1_000_000).toFixed(1) + "M";
  if (n >= 10_000) return (n / 1_000).toFixed(1) + "k";
  return String(n);
}

function JobCard(props: {
  job: Job;
  readOnly: boolean;
  onStart: () => void;
  onStop: () => void;
  onEdit: () => void;
  onDuplicate: () => void;
  onDelete: () => void;
}) {
  const j = props.job;
  return (
    <div className={j.running ? "card running" : "card"}>
      <div className="card-head">
        <span className={j.running ? "dot on" : "dot"} />
        <strong>{j.name}</strong>
        <span className="chip">{j.preset}</span>
      </div>
      <div className="card-dest">
        → {j.host}:{j.port} <span className="chip dim">{j.transport.toUpperCase()}</span>
        {j.format && <span className="chip dim">{j.format}</span>}
        {j.autostart && <span className="chip dim">autostart</span>}
      </div>
      <div className="card-stats">
        <span>
          <em>{j.rate}</em> EPS set
        </span>
        {j.running && (
          <span>
            <em>{j.actualEps.toFixed(1)}</em> actual
          </span>
        )}
        <span>
          <em>{fmtCount(j.sent)}</em> sent
        </span>
        <span className={j.errors > 0 ? "err" : ""}>
          <em>{fmtCount(j.errors)}</em> errors
        </span>
      </div>
      {j.lastError && <div className="card-err">{j.lastError}</div>}
      {!props.readOnly && (
        <div className="card-actions">
          {j.running ? (
            <button className="danger" onClick={props.onStop}>
              ■ Stop
            </button>
          ) : (
            <button className="primary" onClick={props.onStart}>
              ▶ Start
            </button>
          )}
          <button onClick={props.onEdit} disabled={j.running} title={j.running ? "Stop first" : ""}>
            Edit
          </button>
          <button onClick={props.onDuplicate}>Duplicate</button>
          <button className="quiet" onClick={props.onDelete}>
            Delete
          </button>
        </div>
      )}
    </div>
  );
}
