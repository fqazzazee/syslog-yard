import { Handle, Position, type NodeProps, type Node } from "@xyflow/react";
import { SEVERITIES, type GraphNode } from "./api";

export type FlowData = { g: GraphNode };
export type FlowNode = Node<FlowData>;

export function summary(g: GraphNode): string {
  const c = g.config;
  switch (g.type) {
    case "source":
      return `${c.transport} :${c.port}${c.bind && c.bind !== "0.0.0.0" ? ` @${c.bind}` : ""}`;
    case "forward":
      return `${c.host}:${c.port} ${c.transport}`;
    case "filter": {
      const parts = [];
      if (c.severityMax != null) parts.push(`sev ≤ ${SEVERITIES[c.severityMax]}`);
      if (c.program) parts.push(`prog ${c.program}`);
      if (c.match) parts.push(`~ /${c.match}/`);
      return parts.join(" & ") || "no conditions";
    }
    case "cache": {
      const where = c.location ? `share:${c.location}` : "local";
      const keep = [
        c.maxSizeMB ? `${c.maxSizeMB}M` : "daily",
        `×${c.rotate || 7}`,
        c.maxAgeDays ? `${c.maxAgeDays}d` : "",
      ]
        .filter(Boolean)
        .join(" ");
      return `${where}/${c.dir || "…"} keep ${keep}`;
    }
    case "notify":
      return `${c.notifyKind ?? "slack"} → ${hostOf(c.url) || "…"}`;
  }
}

function hostOf(url?: string): string {
  if (!url) return "";
  try {
    return new URL(url).host;
  } catch {
    return url.slice(0, 24);
  }
}

function Label({ g }: { g: GraphNode }) {
  return (
    <div className="nlabel">
      <b>
        {g.name}
        {g.disabled && <em className="off-tag">off</em>}
      </b>
      <span>{summary(g)}</span>
    </div>
  );
}

// cls dims toggled-off nodes; they stay editable but Apply skips them.
function cls(base: string, g: GraphNode): string {
  return g.disabled ? `${base} voff` : base;
}

export function SourceNode({ data }: NodeProps<FlowNode>) {
  return (
    <div className={cls("vnode vsource", data.g)}>
      <Label g={data.g} />
      <Handle type="source" position={Position.Right} />
    </div>
  );
}

export function FilterNode({ data }: NodeProps<FlowNode>) {
  return (
    <div className={cls("vnode vfilter", data.g)}>
      <Handle type="target" position={Position.Left} />
      <Label g={data.g} />
      <div className="ports">
        <span className="port-label match">match</span>
        <span className="port-label else">else</span>
      </div>
      <Handle id="match" type="source" position={Position.Right} style={{ top: "35%" }} className="h-match" />
      <Handle id="else" type="source" position={Position.Right} style={{ top: "75%" }} className="h-else" />
    </div>
  );
}

export function SinkNode({ data }: NodeProps<FlowNode>) {
  return (
    <div className={cls(`vnode v${data.g.type}`, data.g)}>
      <Handle type="target" position={Position.Left} />
      <Label g={data.g} />
    </div>
  );
}

export const nodeTypes = {
  vsource: SourceNode,
  vfilter: FilterNode,
  vsink: SinkNode,
};

export function rfType(t: GraphNode["type"]): keyof typeof nodeTypes {
  if (t === "source") return "vsource";
  if (t === "filter") return "vfilter";
  return "vsink";
}
