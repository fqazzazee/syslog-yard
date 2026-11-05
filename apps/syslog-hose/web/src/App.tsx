import { useEffect, useRef, useState } from "react";
import { AppShell } from "../../../shared/web/src/AppShell";
import { useHashRoute } from "../../../shared/web/src/hooks";
import { errorText } from "../../../shared/web/src/http";
import { Login } from "../../../shared/web/src/Login";
import { Badge, Banner, Button, EmptyState, PageHeader } from "../../../shared/web/src/ui";
import { api, type AuthUser, type Job, type PresetSummary, type TailEvent } from "./api";
import { JobForm } from "./JobForm";
import { PresetsView } from "./PresetsView";
import { Tail, type TailRow } from "./Tail";

const SECTIONS = ["jobs", "presets", "tail"] as const;
type SectionId = (typeof SECTIONS)[number];
const TITLES: Record<SectionId, string> = { jobs: "Jobs", presets: "Presets", tail: "Live tail" };

type AuthState = { enabled: boolean; user: AuthUser | null; expired?: boolean };

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
    const expired = () => setAuth((a) => (a?.enabled && a.user ? { enabled: true, user: null, expired: true } : a));
    window.addEventListener("auth-expired", expired);
    return () => window.removeEventListener("auth-expired", expired);
  }, []);

  if (auth === undefined) return null;
  if (auth.enabled && !auth.user) {
    return (
      <Login
        tool="hose"
        notice={auth.expired ? "Your session ended — sign in again." : undefined}
        onLogin={(user) => setAuth({ enabled: true, user })}
      />
    );
  }
  return (
    <Workspace
      user={auth.user}
      onSignOut={() => api.logout().finally(() => setAuth({ enabled: true, user: null }))}
    />
  );
}

function Workspace({ user, onSignOut }: { user: AuthUser | null; onSignOut: () => void }) {
  const [path, navigate] = useHashRoute();
  const routed = (SECTIONS as readonly string[]).includes(path[0]) ? (path[0] as SectionId) : null;
  const section: SectionId = routed ?? "jobs";
  const [jobs, setJobs] = useState<Job[]>([]);
  const [presets, setPresets] = useState<PresetSummary[]>([]);
  const [events, setEvents] = useState<TailRow[]>([]);
  const nextUid = useRef(0);
  const [editing, setEditing] = useState<Partial<Job> | null>(null);
  const [error, setError] = useState("");
  const [showTail, setShowTail] = useState(true);
  const [paused, setPaused] = useState(false);
  const [hints, setHints] = useState<Record<string, string>>({});
  const pausedRef = useRef(false);
  pausedRef.current = paused;
  const readOnly = user?.role === "viewer";

  // Unknown or empty hash: land on Jobs without adding a history entry.
  useEffect(() => {
    if (!routed) navigate(["jobs"], { replace: true });
  }, [routed, navigate]);

  const refreshPresets = () => api.presets().then(setPresets).catch(() => {});

  useEffect(() => {
    refreshPresets();
    api.hints().then(setHints).catch(() => {});
    const es = new EventSource("/api/stream");
    es.onmessage = (m) => {
      let data: { jobs?: Job[]; events?: TailEvent[] };
      try {
        data = JSON.parse(m.data) as typeof data;
      } catch {
        return; // a malformed frame must not kill the stream handler
      }
      setJobs(data.jobs ?? []);
      const incoming = data.events ?? [];
      if (!pausedRef.current && incoming.length) {
        const rows = incoming.map((e) => ({ ...e, uid: ++nextUid.current }));
        setEvents((prev) => [...prev, ...rows].slice(-300));
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
      .catch((e: unknown) => setError(errorText(e)));
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

  const tailProps = {
    events,
    jobs,
    paused,
    onPause: setPaused,
    onClear: () => setEvents([]),
  };

  return (
    <AppShell
      tool="hose"
      links={hints}
      section={section}
      title={TITLES[section]}
      user={user}
      onSignOut={onSignOut}
      sectionBadges={{
        jobs: running > 0 ? (
          <Badge tone="accent" title={`${running} running`}>
            {running}
          </Badge>
        ) : null,
      }}
    >
      {error && (
        <Banner className="page-banner" onDismiss={() => setError("")}>
          {error}
        </Banner>
      )}

      {section === "jobs" && (
        <>
          <PageHeader
            title="Jobs"
            icon="bolt"
            meta={running > 0 && <Badge tone="accent">{running} running</Badge>}
            actions={
              !readOnly && (
                <>
                  {running > 0 && (
                    <Button variant="danger" icon="stop" onClick={() => act(api.stopAll)}>
                      Stop all
                    </Button>
                  )}
                  <Button variant="primary" icon="add" onClick={() => setEditing(newJob())}>
                    New job
                  </Button>
                </>
              )
            }
          />
          <div className="page">
            {jobs.length === 0 ? (
              <EmptyState icon="water_drop" title="No jobs yet">
                {readOnly ? "Jobs created by analysts appear here." : "Create one to start spraying syslog at something."}
              </EmptyState>
            ) : (
              <div className="cards">
                {jobs.map((j) => (
                  <JobCard
                    key={j.id}
                    job={j}
                    readOnly={readOnly}
                    onStart={() => act(() => api.startJob(j.id))}
                    onStop={() => act(() => api.stopJob(j.id))}
                    onEdit={() => setEditing(j)}
                    onDuplicate={() => setEditing({ ...j, id: undefined, name: `${j.name} (copy)` } as Partial<Job>)}
                    onDelete={() => {
                      if (confirm(`Delete job "${j.name}"?`)) act(() => api.deleteJob(j.id));
                    }}
                  />
                ))}
              </div>
            )}
          </div>
          <Tail {...tailProps} variant="drawer" open={showTail} onToggle={() => setShowTail(!showTail)} />
        </>
      )}

      {section === "presets" && (
        <PresetsView
          presets={presets}
          readOnly={readOnly}
          routeName={path[1]}
          onOpen={(name) => navigate(name ? ["presets", name] : ["presets"])}
          onChanged={refreshPresets}
        />
      )}

      {section === "tail" && (
        <>
          <PageHeader title="Live tail" icon="terminal" meta="Everything the running jobs send, newest last" />
          <Tail {...tailProps} variant="page" />
        </>
      )}

      {editing !== null && (
        <JobForm
          initial={editing}
          presets={presets}
          onClose={() => setEditing(null)}
          onSaved={() => {
            setEditing(null);
            api
              .jobs()
              .then(setJobs)
              .catch((e: unknown) => setError(errorText(e)));
          }}
        />
      )}
    </AppShell>
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
  const titleId = `job-${j.id}-title`;
  return (
    <article className={j.running ? "card running" : "card"} aria-labelledby={titleId}>
      <div className="card-head">
        <span className={j.running ? "dot on" : "dot"} role="img" aria-label={j.running ? "running" : "stopped"} />
        <h2 id={titleId}>{j.name}</h2>
        <Badge>{j.preset}</Badge>
      </div>
      <div className="card-dest">
        → {j.host}:{j.port} <span className="chip">{j.transport.toUpperCase()}</span>
        {j.format && <span className="chip">{j.format}</span>}
        {j.autostart && <span className="chip">autostart</span>}
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
            <Button variant="danger" icon="stop" onClick={props.onStop}>
              Stop
            </Button>
          ) : (
            <Button variant="primary" icon="play_arrow" onClick={props.onStart}>
              Start
            </Button>
          )}
          <Button icon="edit" onClick={props.onEdit} disabled={j.running} title={j.running ? "Stop the job first" : undefined}>
            Edit
          </Button>
          <Button onClick={props.onDuplicate}>Duplicate</Button>
          <Button variant="quiet" icon="delete" onClick={props.onDelete}>
            Delete
          </Button>
        </div>
      )}
    </article>
  );
}
