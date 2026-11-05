import { useCallback, useEffect, useMemo, useRef, useState } from "react";
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
import { AppShell } from "../../../shared/web/src/AppShell";
import { useHashRoute, useVisibleInterval } from "../../../shared/web/src/hooks";
import { ApiError, errorText } from "../../../shared/web/src/http";
import { Icon } from "../../../shared/web/src/Icon";
import { Login } from "../../../shared/web/src/Login";
import { Menu } from "../../../shared/web/src/Menu";
import { getTheme } from "../../../shared/web/src/theme";
import { toast } from "../../../shared/web/src/Toast";
import { Badge, Banner, Button, EmptyState, PageHeader, TabPanel, Tabs, type Tone } from "../../../shared/web/src/ui";
import {
  api,
  type ActivateResult,
  type AuthUser,
  type Graph,
  type GraphNode,
  type NodeType,
  type Status,
  type HistoryEntry,
} from "./api";
import { nodeTypes, rfType, type FlowNode } from "./FlowNodes";
import { NodePanel } from "./NodePanel";
import { TailView } from "./TailView";

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

// fmtEps renders a per-second message rate compactly; undefined for no/zero
// flow so an idle wire just shows its structural label (or nothing).
function fmtEps(r: number | undefined): string | undefined {
  if (r === undefined || r <= 0) return undefined;
  if (r < 1) return `${r.toFixed(2)}/s`;
  if (r < 10) return `${r.toFixed(1)}/s`;
  return `${Math.round(r)}/s`;
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
  notify: { notifyKind: "slack", url: "", ratePerMin: 30 },
};

const NEW_NAMES: Record<NodeType, string> = {
  source: "internal in",
  filter: "severity filter",
  forward: "forward",
  cache: "cache",
  notify: "notify",
};


const SECTIONS = ["flow", "history", "tail"] as const;
type SectionId = (typeof SECTIONS)[number];
const TITLES: Record<SectionId, string> = { flow: "Flow", history: "History", tail: "Live tail" };

type AuthState = { enabled: boolean; user: AuthUser | null; expired?: boolean };

// graphKey is a stable fingerprint of what Save would send, used to tell
// whether the canvas differs from the last saved graph.
const graphKey = (g: Graph) => JSON.stringify(g);

// A rejected graph names the offending node(s) in quotes (node "fw in": …),
// by name or id; find them so the canvas and the node panel can point at
// them.
function nodesNamedIn(msg: string, nodes: FlowNode[]): string[] {
  const quoted = [...msg.matchAll(/"([^"]+)"/g)].map((m) => m[1]);
  if (quoted.length === 0) return [];
  return nodes.filter((n) => quoted.includes(n.data.g.name) || quoted.includes(n.id)).map((n) => n.id);
}

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
        tool="valve"
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
  const section: SectionId = routed ?? "flow";
  const [nodes, setNodes, onNodesChange] = useNodesState<FlowNode>([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState<Edge>([]);
  const [selected, setSelected] = useState<string | null>(null);
  const [status, setStatus] = useState<Status | null>(null);
  const [eps, setEps] = useState<Record<string, number>>({});
  const prevTp = useRef<{ counts: Record<string, number>; t: number } | null>(null);
  const nodesRef = useRef<FlowNode[]>([]);
  nodesRef.current = nodes;
  const [conf, setConf] = useState("");
  const [history, setHistory] = useState<HistoryEntry[]>([]);
  const [hints, setHints] = useState<Record<string, string>>({});
  const [banner, setBanner] = useState<{ kind: Tone; text: string } | null>(null);
  // The last graph rejection, with the nodes it names.
  const [graphError, setGraphError] = useState<{ text: string; nodeIds: string[] } | null>(null);
  const [preview, setPreview] = useState<{ id: string; conf: string } | null>(null);
  const [tailOn, setTailOn] = useState(false);
  const [theme, setTheme] = useState(getTheme());
  const [historyTab, setHistoryTab] = useState<"applied" | "active">("applied");
  const importInput = useRef<HTMLInputElement>(null);
  const [savedKey, setSavedKey] = useState<string | null>(null);
  const readOnly = user?.role === "viewer";

  useEffect(() => {
    if (!routed) navigate(["flow"], { replace: true });
  }, [routed, navigate]);

  // applyStatus stores the status and turns the cumulative per-node counters
  // into a per-second rate from the delta since the previous poll.
  const applyStatus = useCallback((st: Status | null) => {
    setStatus(st);
    // No counters (syslog-ng down, or the status call failed): clear the
    // rates and the baseline so wires don't keep showing the last number.
    const tp = st?.running ? st.throughput : undefined;
    if (!tp) {
      prevTp.current = null;
      setEps((e) => (Object.keys(e).length === 0 ? e : {}));
      return;
    }
    const now = Date.now();
    const prev = prevTp.current;
    if (prev) {
      const dt = (now - prev.t) / 1000;
      if (dt > 0.5) {
        const next: Record<string, number> = {};
        for (const [id, cur] of Object.entries(tp)) {
          const p = prev.counts[id];
          next[id] = p == null || cur < p ? 0 : (cur - p) / dt; // reset → 0
        }
        setEps(next);
      }
    }
    prevTp.current = { counts: tp, t: now };
  }, []);

  const refresh = useCallback(() => {
    api.status().then(applyStatus).catch(() => applyStatus(null));
    api.config().then(setConf).catch(() => {});
    api.history().then(setHistory).catch(() => {});
  }, [applyStatus]);

  const loadGraph = (g: Graph) => {
    const f = toFlow(g);
    setNodes(f.nodes);
    setEdges(f.edges);
    setSavedKey(graphKey(fromFlow(f.nodes, f.edges)));
    setGraphError(null);
  };

  useEffect(() => {
    api
      .getGraph()
      .then(loadGraph)
      .catch((e) => setBanner({ kind: "error", text: errorText(e) }));
    api.hints().then(setHints).catch(() => {});
    refresh();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [refresh, setNodes, setEdges]);

  // Status every 3s while the tab is visible (the mount refresh covers t=0).
  useVisibleInterval(
    () => {
      api.status().then(applyStatus).catch(() => applyStatus(null));
    },
    3000,
    [],
    { immediate: false },
  );

  // Unsaved-changes tracking: compare the canvas with the last graph loaded
  // from or saved to the server (savedKey is null until the first load).
  const dirty = savedKey !== null && graphKey(fromFlow(nodes, edges)) !== savedKey;
  useEffect(() => {
    if (!dirty || readOnly) return;
    const warn = (e: BeforeUnloadEvent) => {
      e.preventDefault();
      e.returnValue = "";
    };
    window.addEventListener("beforeunload", warn);
    return () => window.removeEventListener("beforeunload", warn);
  }, [dirty, readOnly]);

  // Label the wires with live throughput. A wire into a sink shows that
  // sink's rate (post-filter delivered); a wire out of a source shows the
  // source's rate. Filter→filter wires have no driver counter. Derived at
  // render (not written back into edge state) so wires loaded or drawn after
  // the last poll are labelled too, and nothing animates while syslog-ng is
  // not running.
  const running = status?.running ?? false;
  const typeKey = nodes.map((n) => `${n.id}\u0000${n.data.g.type}`).join("\u0001");
  const nodeType = useMemo(() => {
    const type: Record<string, string> = {};
    for (const n of nodesRef.current) type[n.id] = n.data.g.type;
    return type;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [typeKey]);
  const shownEdges = useMemo(
    () =>
      edges.map((e) => {
        const isElse = e.sourceHandle === "else";
        let rate: number | undefined;
        if (["forward", "cache", "notify"].includes(nodeType[e.target])) rate = eps[e.target];
        else if (nodeType[e.source] === "source") rate = eps[e.source];
        const rateLabel = fmtEps(rate);
        const label = [isElse ? "else" : null, rateLabel].filter(Boolean).join(" · ") || undefined;
        const animated = running && (rate === undefined ? true : rate > 0);
        return { ...e, label, animated, className: isElse ? "edge-else" : undefined };
      }),
    [edges, eps, running, nodeType],
  );

  // Nodes named by the last rejection get an error outline on the canvas.
  const errorIds = graphError?.nodeIds ?? [];
  const errorKey = errorIds.join("\u0000");
  const shownNodes = useMemo(
    () =>
      errorIds.length === 0
        ? nodes
        : nodes.map((n) => (errorIds.includes(n.id) ? { ...n, className: "has-error" } : n)),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [nodes, errorKey],
  );

  const onConnect = useCallback(
    (c: Connection) => {
      if (readOnly) return;
      setEdges((es) => addEdge(mkEdge(c.source!, c.target!, c.sourceHandle), es));
    },
    [setEdges, readOnly],
  );

  const addNode = (type: NodeType, init?: { name: string; config: Partial<GraphNode["config"]> }) => {
    const id = `${type}-${Date.now().toString(36)}`;
    const col = { source: 60, filter: 320, forward: 620, cache: 620, notify: 620 }[type];
    const g: GraphNode = {
      id,
      type,
      name: init?.name ?? NEW_NAMES[type],
      x: col,
      y: 80 + nodes.length * 70,
      config: { ...DEFAULTS[type], ...init?.config },
    };
    if (type === "forward" && hints.suggestedForward) {
      const [h, p] = hints.suggestedForward.split(":");
      g.name = `to ${h}`;
      g.config.host = h;
      g.config.port = Number(p) || 514;
    }
    setNodes((ns) => [...ns, { id, type: rfType(type), position: { x: g.x, y: g.y }, data: { g } }]);
    setSelected(id);
  };

  const updateSelected = (g: GraphNode) => {
    if (readOnly) return;
    setNodes((ns) => ns.map((n) => (n.id === g.id ? { ...n, data: { g } } : n)));
  };

  // Drops a node and its wires from the draft; like add/edit it only
  // touches the live config on Apply.
  const deleteNode = (id: string) => {
    setNodes((ns) => ns.filter((n) => n.id !== id));
    setEdges((es) => es.filter((e) => e.source !== id && e.target !== id));
    setSelected((s) => (s === id ? null : s));
  };

  // showFailure reports a failed save/apply/rollback. A graph rejection
  // (422) that names nodes also outlines them and selects the first.
  const showFailure = (e: unknown, prefix = "") => {
    const text = prefix + errorText(e);
    const ids = e instanceof ApiError && e.status === 422 ? nodesNamedIn(errorText(e), nodesRef.current) : [];
    setGraphError(ids.length ? { text, nodeIds: ids } : null);
    if (ids.length) setSelected(ids[0]);
    setBanner({ kind: "error", text });
  };

  const save = async (): Promise<boolean> => {
    try {
      const g = fromFlow(nodes, edges);
      await api.saveGraph(g);
      setSavedKey(graphKey(g));
      setGraphError(null);
      return true;
    } catch (e) {
      showFailure(e, e instanceof ApiError && e.status === 413 ? "The graph is too large to save: " : "Not saved: ");
      return false;
    }
  };

  const activated = (r: ActivateResult, ok: string) => {
    if (r?.warning) setBanner({ kind: "warning", text: `${ok}, but syslog-ng did not confirm it: ${r.warning}` });
    else {
      setBanner(null);
      toast(ok);
    }
  };

  const apply = async () => {
    if (!(await save())) return;
    try {
      activated(await api.apply(), "Applied — syslog-ng reloaded");
    } catch (e) {
      showFailure(e);
    }
    refresh();
  };

  const rollback = async (id: string, time: string) => {
    const lose = dirty ? " Unsaved changes on the canvas will be lost." : "";
    if (
      !confirm(
        `Roll back to the config applied ${new Date(time).toLocaleString()}? This reloads syslog-ng now and replaces the graph.${lose}`,
      )
    ) {
      return;
    }
    try {
      const r = await api.rollback(id);
      loadGraph(await api.getGraph());
      setSelected(null);
      setPreview(null);
      activated(r, `Rolled back to ${new Date(time).toLocaleString()}`);
    } catch (e) {
      setBanner({ kind: "error", text: `Rollback failed: ${errorText(e)}` });
    }
    // A rollback is recorded as a new history entry.
    refresh();
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
    const lose = dirty ? " Unsaved changes on the canvas will be lost." : "";
    if (
      !confirm(
        `Import ${file.name}? It replaces the saved graph immediately (Apply is still needed to activate it).${lose}`,
      )
    ) {
      return;
    }
    try {
      const g = JSON.parse(await file.text()) as Graph;
      await api.saveGraph(g);
      loadGraph(g);
      setSelected(null);
      setBanner(null);
      toast(`Imported ${file.name} — Apply to activate`);
    } catch (e) {
      setBanner({ kind: "error", text: `Import failed: ${errorText(e)}` });
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
      .catch((e) => setBanner({ kind: "error", text: errorText(e) }));
  };

  const sel = nodes.find((n) => n.id === selected)?.data.g ?? null;
  const shares = (hints.shares ?? "").split(",").filter(Boolean);

  const addItems = [
    {
      id: "internal",
      label: "Internal IN",
      icon: "add" as const,
      title: "Listen inside the yard network (the hose and other internal services send here)",
      onSelect: () => addNode("source"),
    },
    // External entry point: deploy/compose.yaml publishes host 6514
    // (udp+tcp) to container 6514, so this block is where off-host senders
    // land. Its enabled toggle is the "allow external sources" switch.
    {
      id: "external",
      label: "External IN",
      icon: "add" as const,
      title: "Listen for syslog from other machines (host port 6514)",
      onSelect: () => addNode("source", { name: "external syslog", config: { transport: "udp+tcp", port: 6514 } }),
    },
    { id: "filter", label: "Filter", icon: "add" as const, onSelect: () => addNode("filter") },
    { id: "forward", label: "OUT port", icon: "add" as const, onSelect: () => addNode("forward") },
    { id: "cache", label: "Cache", icon: "add" as const, onSelect: () => addNode("cache") },
    { id: "notify", label: "Notify", icon: "add" as const, onSelect: () => addNode("notify") },
  ];

  const statusLine = (
    <span className="valve-status">
      <span className={`dot ${status?.running ? "on" : "off"}`} aria-hidden="true" />
      {status?.running
        ? `syslog-ng ${status.version} running (pid ${status.pid}, ${status.restarts} restarts)`
        : "syslog-ng not running"}
      {status?.lastError && <span className="err"> — {status.lastError}</span>}
    </span>
  );

  return (
    <AppShell
      tool="valve"
      links={hints}
      section={section}
      title={TITLES[section]}
      user={user}
      onSignOut={onSignOut}
      onThemeChange={setTheme}
      sectionBadges={{ flow: dirty && !readOnly ? <Badge tone="warning" title="unsaved changes">•</Badge> : null }}
    >
      {banner && (
        <Banner kind={banner.kind} className="page-banner" onDismiss={() => setBanner(null)}>
          {banner.text}
        </Banner>
      )}

      {section === "flow" && (
        <>
          <PageHeader
            className="flow-header"
            title="Flow"
            icon="account_tree"
            meta={
              <>
                {readOnly && <Badge>read-only</Badge>}
                {dirty && !readOnly && (
                  <Badge tone="warning" title="The canvas differs from the saved graph">
                    unsaved changes
                  </Badge>
                )}
              </>
            }
            actions={
              <>
                {!readOnly && (
                  <Menu
                    triggerClassName="add-node"
                    align="start"
                    trigger={
                      <>
                        <Icon name="add" size={16} /> Add node <Icon name="keyboard_arrow_down" size={16} />
                      </>
                    }
                    items={addItems}
                  />
                )}
                <Button icon="download" onClick={exportGraph} title="Download the graph as JSON">
                  Export
                </Button>
                {!readOnly && (
                  <>
                    <Button icon="upload" onClick={() => importInput.current?.click()} title="Load a graph JSON file">
                      Import
                    </Button>
                    <input
                      ref={importInput}
                      type="file"
                      accept=".json,application/json"
                      hidden
                      aria-hidden="true"
                      tabIndex={-1}
                      onChange={(e) => {
                        const f = e.target.files?.[0];
                        if (f) void importGraph(f);
                        e.target.value = "";
                      }}
                    />
                    <Button variant="primary" icon="check" onClick={() => void apply()}>
                      Apply
                    </Button>
                  </>
                )}
              </>
            }
          />
          <div className="flow-main">
            <div className="canvas" aria-label="Flow canvas" role="region">
              <ReactFlow
                nodes={shownNodes}
                edges={shownEdges}
                nodeTypes={nodeTypes}
                onNodesChange={onNodesChange}
                onEdgesChange={onEdgesChange}
                onConnect={onConnect}
                nodesDraggable={!readOnly}
                nodesConnectable={!readOnly}
                edgesReconnectable={!readOnly}
                onNodeClick={(_, n) => setSelected(n.id)}
                onPaneClick={() => setSelected(null)}
                deleteKeyCode={readOnly ? null : ["Backspace", "Delete"]}
                fitView
                colorMode={theme}
              >
                <Background />
                <Controls />
              </ReactFlow>
              {nodes.length === 0 && (
                <div className="empty-hint">
                  Add an <b>IN port</b>, a <b>Filter</b>, and an <b>OUT port</b> or <b>Cache</b>; wire them, then{" "}
                  <b>Apply</b>.
                </div>
              )}
            </div>
            <aside className="node-aside" aria-label="Node settings">
              {sel ? (
                <NodePanel
                  key={sel.id}
                  node={sel}
                  readOnly={readOnly}
                  shares={shares}
                  error={graphError && graphError.nodeIds.includes(sel.id) ? graphError.text : undefined}
                  onChange={updateSelected}
                  onDelete={readOnly ? undefined : () => deleteNode(sel.id)}
                />
              ) : (
                <EmptyState icon="account_tree" title="No node selected">
                  Select a node on the canvas to edit it.
                </EmptyState>
              )}
            </aside>
          </div>
          {tailOn && <TailView variant="drawer" />}
          <footer className="valve-footer">
            {statusLine}
            <span className="spacer" />
            <Button
              size="sm"
              className={tailOn ? "tail-toggle on" : "tail-toggle"}
              icon={tailOn ? "keyboard_arrow_down" : "keyboard_arrow_up"}
              aria-expanded={tailOn}
              onClick={() => setTailOn(!tailOn)}
            >
              Live tail
            </Button>
          </footer>
        </>
      )}

      {section === "history" && (
        <>
          <PageHeader title="History" icon="history" meta={statusLine} />
          <div className="page history-page">
            <Tabs
              idBase="hist"
              label="History views"
              value={historyTab}
              onChange={(t) => {
                setHistoryTab(t);
                if (t === "active") refresh();
              }}
              tabs={[
                { id: "applied", label: `Applied configs (${history.length})` },
                { id: "active", label: "Active syslog-ng config" },
              ]}
            />
            {historyTab === "applied" ? (
              <TabPanel idBase="hist" id="applied">
                {history.length === 0 ? (
                  <EmptyState icon="history" title="Nothing applied yet">
                    Every Apply and rollback is recorded here with its config, ready to roll back to.
                  </EmptyState>
                ) : (
                  <div className="table-scroll">
                    <table className="data-table">
                      <thead>
                        <tr>
                          <th scope="col">Applied</th>
                          <th scope="col">Id</th>
                          <th scope="col">
                            <span className="sr-only">Actions</span>
                          </th>
                        </tr>
                      </thead>
                      <tbody>
                        {history.map((h, i) => (
                          <HistoryRow
                            key={h.id}
                            entry={h}
                            current={i === 0}
                            open={preview?.id === h.id}
                            conf={preview?.id === h.id ? preview.conf : ""}
                            readOnly={readOnly}
                            onView={() => togglePreview(h.id)}
                            onRollback={() => void rollback(h.id, h.time)}
                          />
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </TabPanel>
            ) : (
              <TabPanel idBase="hist" id="active">
                <pre className="conf">{conf || "No config loaded."}</pre>
              </TabPanel>
            )}
          </div>
        </>
      )}

      {section === "tail" && (
        <>
          <PageHeader title="Live tail" icon="terminal" meta="Every message entering the valve, by IN port" />
          <TailView variant="page" />
        </>
      )}
    </AppShell>
  );
}

function HistoryRow(props: {
  entry: HistoryEntry;
  current: boolean;
  open: boolean;
  conf: string;
  readOnly: boolean;
  onView: () => void;
  onRollback: () => void;
}) {
  const { entry: h } = props;
  const when = new Date(h.time).toLocaleString();
  return (
    <>
      <tr>
        <td>
          {when} {props.current && <Badge tone="success">latest</Badge>}
        </td>
        <td className="mono muted">{h.id}</td>
        <td className="row-actions">
          <Button size="sm" aria-expanded={props.open} onClick={props.onView} aria-label={`${props.open ? "Hide" : "View"} config applied ${when}`}>
            {props.open ? "Hide" : "View"}
          </Button>{" "}
          {!props.readOnly && (
            <Button size="sm" icon="history" onClick={props.onRollback} aria-label={`Roll back to config applied ${when}`}>
              Roll back
            </Button>
          )}
        </td>
      </tr>
      {props.open && (
        <tr className="hist-preview">
          <td colSpan={3}>
            <pre className="conf">{props.conf}</pre>
          </td>
        </tr>
      )}
    </>
  );
}
