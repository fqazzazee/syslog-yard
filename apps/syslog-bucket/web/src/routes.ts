// Hash routes of the bucket UI. Every view is addressable, so the shared
// side nav (and the other tools) can deep-link into it and back/forward
// walk the views:
//
//   #/logs                         all logs
//   #/buckets          #/buckets/<id>          bucket list / one bucket's logs
//   #/tags/<id>                    logs with a tag
//   #/attack           #/attack/<technique>    ATT&CK matrix / its logs
//   #/ot               #/ot/<alert>            ICS/OT matrix / its logs
//   #/network                      network security view
//   #/frameworks       #/frameworks/<fw>[/<item>]  framework list / matrix / logs
//   #/rules                        rule list
import type { Selection } from "./types";

export type Page = "buckets" | "frameworks" | "rules";

// A route is a log/matrix selection or one of the list pages.
export type Route = { section: string; selection: Selection } | { section: string; page: Page };

export function parseRoute(path: string[]): Route | null {
  const [head, a, b] = path;
  const id = (v: string | undefined) => (v && /^\d+$/.test(v) ? Number(v) : null);
  switch (head) {
    case "logs":
      return { section: "logs", selection: { kind: "all" } };
    case "buckets": {
      if (a === undefined) return { section: "buckets", page: "buckets" };
      const n = id(a);
      return n === null ? null : { section: "buckets", selection: { kind: "bucket", id: n } };
    }
    case "tags": {
      const n = id(a);
      return n === null ? null : { section: "logs", selection: { kind: "tag", id: n } };
    }
    case "attack":
      return { section: "attack", selection: a ? { kind: "technique", id: a } : { kind: "mitre" } };
    case "ot":
      return { section: "ot", selection: a ? { kind: "otalert", id: a } : { kind: "ot" } };
    case "network":
      return { section: "network", selection: { kind: "net" } };
    case "frameworks":
      if (!a) return { section: "frameworks", page: "frameworks" };
      return {
        section: "frameworks",
        selection: b ? { kind: "frameworkitem", fw: a, id: b } : { kind: "framework", fw: a },
      };
    case "rules":
      return { section: "rules", page: "rules" };
    default:
      return null;
  }
}

export function pathFor(sel: Selection): string[] {
  switch (sel.kind) {
    case "all":
      return ["logs"];
    case "bucket":
      return ["buckets", String(sel.id)];
    case "tag":
      return ["tags", String(sel.id)];
    case "mitre":
      return ["attack"];
    case "technique":
      return ["attack", sel.id];
    case "ot":
      return ["ot"];
    case "otalert":
      return ["ot", sel.id];
    case "net":
      return ["network"];
    case "framework":
      return ["frameworks", sel.fw];
    case "frameworkitem":
      return ["frameworks", sel.fw, sel.id];
  }
}

export function hrefFor(sel: Selection | Page): string {
  const parts = typeof sel === "string" ? [sel] : pathFor(sel);
  return "#/" + parts.map(encodeURIComponent).join("/");
}
