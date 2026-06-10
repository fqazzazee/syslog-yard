import { useCallback, useEffect, useState } from "react";
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
  type Graph,
  type GraphNode,
  type NodeType,
  type Status,
  type HistoryEntry,
} from "./api";
import { nodeTypes, rfType, type FlowNode } from "./FlowNodes";
import { NodePanel } from "./NodePanel";

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

export default function App() {
  const [nodes, setNodes, onNodesChange] = useNodesState<FlowNode>([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState<Edge>([]);
  const [selected, setSelected] = useState<string | null>(null);
  const [status, setStatus] = useState<Status | null>(null);
  const [conf, setConf] = useState("");
  const [history, setHistory] = useState<HistoryEntry[]>([]);
  const [hints, setHints] = useState<Record<string, string>>({});
  const [banner, setBanner] = useState<{ kind: "ok" | "err"; text: string } | null>(null);

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

  const sel = nodes.find((n) => n.id === selected)?.data.g ?? null;
  const shares = (hints.shares ?? "").split(",").filter(Boolean);

  return (
    <div className="app">
      <header>
        <span className="logo">⊶</span> syslog-valve
        <div className="toolbar">
          <button onClick={() => addNode("source")}>+ IN port</button>
          <button onClick={() => addNode("filter")}>+ Filter</button>
          <button onClick={() => addNode("forward")}>+ OUT port</button>
          <button onClick={() => addNode("cache")}>+ Cache</button>
          <button className="primary" onClick={apply}>
            Apply
          </button>
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
              <div className="hist" key={h.id}>
                <code>{h.id}</code>
                <button onClick={() => rollback(h.id)}>roll back</button>
              </div>
            ))}
          </details>
        </aside>
      </div>
      <footer>
        <span className={`dot ${status?.running ? "on" : "off"}`} />
        {status?.running
          ? `syslog-ng ${status.version} running (pid ${status.pid}, ${status.restarts} restarts)`
          : "syslog-ng not running"}
        {status?.lastError && <span className="err"> — {status.lastError}</span>}
      </footer>
    </div>
  );
}
