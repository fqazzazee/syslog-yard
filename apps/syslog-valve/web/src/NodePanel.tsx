import type { GraphNode } from "./api";

export function NodePanel({
  node,
  onChange,
}: {
  node: GraphNode;
  onChange: (g: GraphNode) => void;
}) {
  const set = (patch: Partial<GraphNode["config"]>) =>
    onChange({ ...node, config: { ...node.config, ...patch } });

  return (
    <div className="panel">
      <h3>{node.type === "source" ? "IN port" : "OUT port"}</h3>
      <label>
        Name
        <input
          value={node.name}
          onChange={(e) => onChange({ ...node, name: e.target.value })}
        />
      </label>
      <label>
        Transport
        <select
          value={node.config.transport}
          onChange={(e) => set({ transport: e.target.value as "udp" | "tcp" })}
        >
          <option value="udp">udp</option>
          <option value="tcp">tcp</option>
        </select>
      </label>
      {node.type === "source" ? (
        <label>
          Bind address
          <input
            value={node.config.bind ?? ""}
            placeholder="0.0.0.0"
            onChange={(e) => set({ bind: e.target.value })}
          />
        </label>
      ) : (
        <label>
          Destination host
          <input
            value={node.config.host ?? ""}
            placeholder="host or IP"
            onChange={(e) => set({ host: e.target.value })}
          />
        </label>
      )}
      <label>
        Port
        <input
          type="number"
          min={1}
          max={65535}
          value={node.config.port}
          onChange={(e) => set({ port: Number(e.target.value) })}
        />
      </label>
      <p className="muted">Changes take effect on Apply.</p>
    </div>
  );
}
