import { useCallback, useEffect, useRef, useState } from "react";
import {
  ReactFlow,
  Background,
  Controls,
  addEdge,
  useNodesState,
  useEdgesState,
  type Edge,
  type Connection,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import {
  api,
  type AuthUser,
  type Graph,
  type GraphNode,
  type NodeType,
  type Status,
  type HistoryEntry,
  type TailEvent,
} from "./api";
import { nodeTypes, rfType, type FlowNode } from "./FlowNodes";
import { Login } from "./Login";
import { NodePanel } from "./NodePanel";
import { YardNav } from "./YardNav";

function mkEdge(from: string, to: string, fromPort?: string | null): Edge {
  return {
    id: `${from}${fromPort ? ":" + fromPort : ""}->${to}`,
    source: from,
    target: to,
    sourceHandle: fromPort || undefined,
    animated: true,
    className: fromPort === "else" ? "edge-else" : undefined,
    label: fromPort === "else" ? "else" : undefined,
  };
}

function toFlow(g: Graph): { nodes: FlowNode[]; edges: Edge[] } {
  return {
    nodes: g.nodes.map((n) => ({
      id: n.id,
      type: rfType(n.type),
      position: { x: n.x, y: n.y },
      data: { g: n },
    })),
    edges: g.edges.map((e) => mkEdge(e.from, e.to, e.fromPort)),
  };
}

function fromFlow(nodes: FlowNode[], edges: Edge[]): Graph {
  return {
    nodes: nodes.map((n) => ({
      ...n.data.g,
      x: n.position.x,
      y: n.position.y,
    })),
    edges: edges.map((e) => ({
      from: e.source,
      fromPort: e.sourceHandle ?? "",
      to: e.target,
    })),
  };
}

const DEFAULTS: Record<NodeType, GraphNode["config"]> = {
  source: { transport: "udp", port: 514, bind: "0.0.0.0" },
  filter: { severityMax: 3 },
  forward: { transport: "udp", port: 514, host: "" },
  cache: { dir: "", rotate: 7, maxSizeMB: 100, maxAgeDays: 14, compress: true },
};

const NEW_NAMES: Record<NodeType, string> = {
  source: "syslog in",
  filter: "severity filter",
  forward: "forward",
  cache: "cache",
};

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
  const [nodes, setNodes, onNodesChange] = useNodesState<FlowNode>([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState<Edge>([]);
  const [selected, setSelected] = useState<string | null>(null);
  const [status, setStatus] = useState<Status | null>(null);
  const [conf, setConf] = useState("");
  const [history, setHistory] = useState<HistoryEntry[]>([]);
  const [hints, setHints] = useState<Record<string, string>>({});
  const [banner, setBanner] = useState<{ kind: "ok" | "err"; text: string } | null>(null);
  const [preview, setPreview] = useState<{ id: string; conf: string } | null>(null);
  const [tailOn, setTailOn] = useState(false);
  const importInput = useRef<HTMLInputElement>(null);
  const readOnly = user?.role === "viewer";

  const refresh = useCallback(() => {
    api.status().then(setStatus).catch(() => setStatus(null));
    api.config().then(setConf).catch(() => {});
    api.history().then(setHistory).catch(() => {});
  }, []);

  useEffect(() => {
    api
      .getGraph()
      .then((g) => {
        const f = toFlow(g);
        setNodes(f.nodes);
        setEdges(f.edges);
      })
      .catch((e) => setBanner({ kind: "err", text: String(e) }));
    api.hints().then(setHints).catch(() => {});
    refresh();
    const t = setInterval(() => api.status().then(setStatus).catch(() => setStatus(null)), 3000);
    return () => clearInterval(t);
  }, [refresh, setNodes, setEdges]);

  const onConnect = useCallback(
    (c: Connection) =>
      setEdges((es) => addEdge(mkEdge(c.source!, c.target!, c.sourceHandle), es)),
    [setEdges],
  );

  const addNode = (type: NodeType) => {
    const id = `${type}-${Date.now().toString(36)}`;
    const col = { source: 60, filter: 320, forward: 620, cache: 620 }[type];
    const g: GraphNode = {
      id,
      type,
      name: NEW_NAMES[type],
      x: col,
      y: 80 + nodes.length * 70,
      config: { ...DEFAULTS[type] },
    };
    if (type === "forward" && hints.suggestedForward) {
      const [h, p] = hints.suggestedForward.split(":");
      g.name = `to ${h}`;
      g.config.host = h;
      g.config.port = Number(p) || 514;
    }
    setNodes((ns) => [
      ...ns,
      { id, type: rfType(type), position: { x: g.x, y: g.y }, data: { g } },
    ]);
    setSelected(id);
  };

  const updateSelected = (g: GraphNode) => {
    setNodes((ns) => (ns.map((n) => (n.id === g.id ? { ...n, data: { g } } : n))));
  };

  const save = async (): Promise<boolean> => {
    try {
      await api.saveGraph(fromFlow(nodes, edges));
      return true;
    } catch (e) {
      setBanner({ kind: "err", text: String(e) });
      return false;
    }
  };

  const apply = async () => {
    if (!(await save())) return;
    try {
      await api.apply();
      setBanner({ kind: "ok", text: "Applied — syslog-ng reloaded" });
      refresh();
    } catch (e) {
      setBanner({ kind: "err", text: String(e) });
    }
  };

  const rollback = async (id: string) => {
    try {
      await api.rollback(id);
      const g = await api.getGraph();
      const f = toFlow(g);
      setNodes(f.nodes);
      setEdges(f.edges);
      setBanner({ kind: "ok", text: `Rolled back to ${id}` });
      refresh();
    } catch (e) {
      setBanner({ kind: "err", text: String(e) });
    }
  };

  // Export the canvas as it stands; import validates server-side first so
  // a bad file can't clobber the saved graph.
  const exportGraph = () => {
    const blob = new Blob([JSON.stringify(fromFlow(nodes, edges), null, 2)], {
      type: "application/json",
    });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = "syslog-valve-graph.json";
    a.click();
    URL.revokeObjectURL(a.href);
  };

  const importGraph = async (file: File) => {
    try {
      const g = JSON.parse(await file.text()) as Graph;
      await api.saveGraph(g);
      const f = toFlow(g);
      setNodes(f.nodes);
      setEdges(f.edges);
      setSelected(null);
      setBanner({ kind: "ok", text: `Imported ${file.name} — Apply to activate` });
    } catch (e) {
      setBanner({ kind: "err", text: `Import failed: ${String(e)}` });
    }
  };

  const togglePreview = (id: string) => {
    if (preview?.id === id) {
      setPreview(null);
      return;
    }
    api
      .historyConfig(id)
      .then((conf) => setPreview({ id, conf }))
      .catch((e) => setBanner({ kind: "err", text: String(e) }));
  };

  const sel = nodes.find((n) => n.id === selected)?.data.g ?? null;
  const shares = (hints.shares ?? "").split(",").filter(Boolean);

  return (
    <div className="app">
      <header>
        <span className="logo">⊶</span> syslog-valve
        <YardNav links={hints} current="valve" />
        <div className="toolbar">
          {!readOnly && (
            <>
              <button onClick={() => addNode("source")}>+ IN port</button>
              <button onClick={() => addNode("filter")}>+ Filter</button>
              <button onClick={() => addNode("forward")}>+ OUT port</button>
              <button onClick={() => addNode("cache")}>+ Cache</button>
            </>
          )}
          <button onClick={exportGraph} title="Download the graph as JSON">
            ⤓ Export
          </button>
          {!readOnly && (
            <>
              <button onClick={() => importInput.current?.click()} title="Load a graph JSON file">
                ⤒ Import
              </button>
              <input
                ref={importInput}
                type="file"
                accept=".json,application/json"
                style={{ display: "none" }}
                onChange={(e) => {
                  const f = e.target.files?.[0];
                  if (f) importGraph(f);
                  e.target.value = "";
                }}
              />
              <button className="primary" onClick={apply}>
                Apply
              </button>
            </>
          )}
          {user && (
            <span className="user-chip">
              👤 {user.display_name || user.username}
              <span className="role-tag">{user.role}</span>
              <button onClick={onSignOut}>Sign out</button>
            </span>
          )}
        </div>
      </header>
      {banner && (
        <div className={`banner ${banner.kind}`} onClick={() => setBanner(null)}>
          {banner.text}
        </div>
      )}
      <div className="main">
        <div className="canvas">
          <ReactFlow
            nodes={nodes}
            edges={edges}
            nodeTypes={nodeTypes}
            onNodesChange={onNodesChange}
            onEdgesChange={onEdgesChange}
            onConnect={onConnect}
            onNodeClick={(_, n) => setSelected(n.id)}
            onPaneClick={() => setSelected(null)}
            fitView
            colorMode="dark"
          >
            <Background />
            <Controls />
          </ReactFlow>
          {nodes.length === 0 && (
            <div className="empty-hint">
              Add an <b>IN port</b>, a <b>Filter</b>, and an <b>OUT port</b> or{" "}
              <b>Cache</b>; wire them, then <b>Apply</b>.
            </div>
          )}
        </div>
        <aside>
          {sel ? (
            <NodePanel node={sel} shares={shares} onChange={updateSelected} />
          ) : (
            <div className="muted">Select a node to edit it.</div>
          )}
          <details onToggle={refresh}>
            <summary>Active syslog-ng config</summary>
            <pre>{conf}</pre>
          </details>
          <details>
            <summary>History ({history.length})</summary>
            {history.map((h) => (
              <div key={h.id}>
                <div className="hist">
                  <code title={h.id}>{new Date(h.time).toLocaleString()}</code>
                  <button onClick={() => togglePreview(h.id)}>
                    {preview?.id === h.id ? "hide" : "view"}
                  </button>
                  {!readOnly && <button onClick={() => rollback(h.id)}>roll back</button>}
                </div>
                {preview?.id === h.id && <pre>{preview.conf}</pre>}
              </div>
            ))}
          </details>
        </aside>
      </div>
      {tailOn && <TailDrawer />}
      <footer>
        <span className={`dot ${status?.running ? "on" : "off"}`} />
        {status?.running
          ? `syslog-ng ${status.version} running (pid ${status.pid}, ${status.restarts} restarts)`
          : "syslog-ng not running"}
        {status?.lastError && <span className="err"> — {status.lastError}</span>}
        <span className="spacer" />
        <button className={tailOn ? "tail-toggle on" : "tail-toggle"} onClick={() => setTailOn(!tailOn)}>
          {tailOn ? "▾ Live tail" : "▸ Live tail"}
        </button>
      </footer>
    </div>
  );
}

// TailDrawer streams every message entering the valve (SSE from the tap
// socket), labeled with the IN port it arrived on.
function TailDrawer() {
  const [events, setEvents] = useState<TailEvent[]>([]);
  const [paused, setPaused] = useState(false);
  const pausedRef = useRef(false);
  pausedRef.current = paused;
  const bodyRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    bodyRef.current?.scrollTo(0, bodyRef.current.scrollHeight);
  }, [events]);

  useEffect(() => {
    const es = new EventSource("/api/tail");
    es.onmessage = (m) => {
      if (pausedRef.current) return;
      const ev = JSON.parse(m.data) as TailEvent;
      setEvents((prev) => [...prev, ev].slice(-300));
    };
    return () => es.close();
  }, []);

  return (
    <div className="tail-drawer">
      <div className="tail-bar">
        <span className="muted">in-flight messages, newest last</span>
        <span className="spacer" />
        <button onClick={() => setPaused(!paused)}>{paused ? "▶ resume" : "‖ pause"}</button>
        <button onClick={() => setEvents([])}>clear</button>
      </div>
      <div className="tail-body" ref={bodyRef}>
        {events.length === 0 && <div className="muted">Waiting for traffic…</div>}
        {events.map((e) => (
          <div className="tail-line" key={e.seq}>
            <span className="tail-src">{e.src}</span>
            <span className="tail-meta">
              {e.time.slice(11, 19)} {e.host} {e.program}:
            </span>{" "}
            {e.message}
          </div>
        ))}
      </div>
    </div>
  );
}
