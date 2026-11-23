import type { Graph } from "./api";

const NODE_TYPES = ["source", "filter", "forward", "cache", "notify"];

const isObject = (v: unknown): v is Record<string, unknown> =>
  typeof v === "object" && v !== null && !Array.isArray(v);

const isCoord = (v: unknown) => typeof v === "number" && Number.isFinite(v);

// parseGraphFile decodes an imported file and throws unless it has the shape
// of a graph, so a wrong file is refused before it can replace the saved one.
// The server still owns validating the values.
export function parseGraphFile(text: string): Graph {
  let g: unknown;
  try {
    g = JSON.parse(text);
  } catch {
    throw new Error("the file is not valid JSON");
  }
  if (!isObject(g) || !Array.isArray(g.nodes) || !Array.isArray(g.edges)) {
    throw new Error('not a graph file: expected "nodes" and "edges" lists');
  }
  g.nodes.forEach((n: unknown, i: number) => {
    if (
      !isObject(n) ||
      typeof n.id !== "string" ||
      typeof n.name !== "string" ||
      !NODE_TYPES.includes(n.type as string) ||
      !isCoord(n.x) ||
      !isCoord(n.y) ||
      !isObject(n.config)
    ) {
      throw new Error(`not a graph file: node ${i + 1} is malformed`);
    }
  });
  g.edges.forEach((e: unknown, i: number) => {
    if (
      !isObject(e) ||
      typeof e.from !== "string" ||
      typeof e.to !== "string" ||
      !(e.fromPort === undefined || e.fromPort === null || typeof e.fromPort === "string")
    ) {
      throw new Error(`not a graph file: edge ${i + 1} is malformed`);
    }
  });
  return g as unknown as Graph;
}
