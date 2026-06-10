import { useCallback, useEffect, useState } from "react";
import {
  ReactFlow,
  Background,
  Controls,
  addEdge,
  useNodesState,
  useEdgesState,
  type Node,
  type Edge,
  type Connection,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import {
  api,
  type Graph,
  type GraphNode,
  type Status,
  type HistoryEntry,
} from "./api";
import { NodePanel } from "./NodePanel";

type FlowData = { label: React.ReactNode; g: GraphNode };
type FlowNode = Node<FlowData>;

function nodeLabel(g: GraphNode): React.ReactNode {
  const detail =
    g.type === "source"
      ? `${g.config.transport} :${g.config.port}`
      : `${g.config.host}:${g.config.port} ${g.config.transport}`;
  return (
    <div className="nlabel">
      <b>{g.name}</b>
      <span>{detail}</span>
    </div>
  );
}

function toFlow(g: Graph): { nodes: FlowNode[]; edges: Edge[] } {
  return {
    nodes: g.nodes.map((n) => ({
      id: n.id,
      type: n.type === "source" ? "input" : "output",
      position: { x: n.x, y: n.y },
      className: `valve-${n.type}`,
      data: { label: nodeLabel(n), g: n },
    })),
    edges: g.edges.map((e) => ({
      id: `${e.from}->${e.to}`,
      source: e.from,
      target: e.to,
      animated: true,
    })),
  };
}

function fromFlow(nodes: FlowNode[], edges: Edge[]): Graph {
  return {
    nodes: nodes.map((n) => ({
      ...n.data.g,
      x: n.position.x,
      y: n.position.y,
    })),
    edges: edges.map((e) => ({ from: e.source, to: e.target })),
  };
}

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
    (c: Connection) => setEdges((es) => addEdge({ ...c, animated: true }, es)),
    [setEdges],
  );

  const addNode = (type: "source" | "forward") => {
    const id = `${type}-${Date.now().toString(36)}`;
    let g: GraphNode;
    if (type === "source") {
      g = {
        id,
        type,
        name: "syslog in",
        x: 80,
        y: 80 + nodes.length * 60,
        config: { transport: "udp", port: 514, bind: "0.0.0.0" },
      };
    } else {
      // pre-fill the next hop in the yard if the deployment suggested one
      const [h, p] = (hints.suggestedForward ?? ":").split(":");
      g = {
        id,
        type,
        name: h ? `to ${h}` : "forward",
        x: 460,
        y: 80 + nodes.length * 60,
        config: { transport: "udp", port: Number(p) || 514, host: h || "" },
      };
    }
    setNodes((ns) => [
      ...ns,
      {
        id,
        type: type === "source" ? "input" : "output",
        position: { x: g.x, y: g.y },
        className: `valve-${type}`,
        data: { label: nodeLabel(g), g },
      },
    ]);
    setSelected(id);
  };

  const updateSelected = (g: GraphNode) => {
    setNodes((ns) =>
      ns.map((n) => (n.id === g.id ? { ...n, data: { label: nodeLabel(g), g } } : n)),
    );
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

  return (
    <div className="app">
      <header>
        <span className="logo">⊶</span> syslog-valve
        <div className="toolbar">
          <button onClick={() => addNode("source")}>+ IN port</button>
          <button onClick={() => addNode("forward")}>+ OUT port</button>
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
              Add an <b>IN port</b> and an <b>OUT port</b>, wire them together, then <b>Apply</b>.
            </div>
          )}
        </div>
        <aside>
          {sel ? (
            <NodePanel node={sel} onChange={updateSelected} />
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
