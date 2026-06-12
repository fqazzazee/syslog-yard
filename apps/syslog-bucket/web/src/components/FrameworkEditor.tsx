import { useState } from "react";
import { createFramework, deleteFramework, updateFramework } from "./../api";
import type { Framework, MitreCatalog, OTCatalog } from "./../types";
import { DEVICE_CLASSES } from "./../types";
import { Icon } from "./Icon";
import Modal from "./Modal";

interface Props {
  framework: Framework | null; // null = new
  mitreCatalog: MitreCatalog | null;
  otCatalog: OTCatalog | null;
  onClose: (changed: boolean) => void;
}

// An editor row: a free-text group label plus the codes the cell maps to.
interface ItemDraft {
  name: string;
  group: string; // group label (slugged to an id on save)
  mitre: string[];
  ot: string[];
  class: string[];
}

function slug(s: string): string {
  return s.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "");
}

// CodeChips edits a string[] against a fixed option list: chips + an add menu.
function CodeChips({
  codes,
  options,
  label,
  onChange,
}: {
  codes: string[];
  options: { id: string; name: string }[];
  label: string;
  onChange: (codes: string[]) => void;
}) {
  const left = options.filter((o) => !codes.includes(o.id));
  return (
    <div className="code-list">
      {codes.map((c) => (
        <span key={c} className="mitre-chip editable">
          {c}
          <button className="chip-x" type="button" title="Remove" onClick={() => onChange(codes.filter((x) => x !== c))}>
            <Icon name="close" size={12} />
          </button>
        </span>
      ))}
      {left.length > 0 && (
        <select className="code-picker" value="" onChange={(e) => e.target.value && onChange([...codes, e.target.value])}>
          <option value="">{label}</option>
          {left.map((o) => (
            <option key={o.id} value={o.id}>
              {o.id}
              {o.name && o.id !== o.name ? ` — ${o.name}` : ""}
            </option>
          ))}
        </select>
      )}
    </div>
  );
}

export default function FrameworkEditor({ framework, mitreCatalog, otCatalog, onClose }: Props) {
  const groupName = (id: string) => framework?.groups.find((g) => g.id === id)?.name ?? id;
  const [name, setName] = useState(framework?.name ?? "");
  const [short, setShort] = useState(framework?.short ?? "");
  const [desc, setDesc] = useState(framework?.desc ?? "");
  const [items, setItems] = useState<ItemDraft[]>(
    framework?.items.map((it) => ({
      name: it.name,
      group: groupName(it.group),
      mitre: it.mitre ?? [],
      ot: it.ot ?? [],
      class: it.class ?? [],
    })) ?? [{ name: "", group: "General", mitre: [], ot: [], class: [] }],
  );
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const mitreOpts = mitreCatalog?.techniques ?? [];
  const otOpts = otCatalog?.alert_types ?? [];
  const classOpts = DEVICE_CLASSES.map((c) => ({ id: c, name: c }));

  const patchItem = (i: number, patch: Partial<ItemDraft>) =>
    setItems(items.map((it, j) => (j === i ? { ...it, ...patch } : it)));

  // Assemble a Framework doc the API will accept: derive groups from the
  // distinct labels, generate stable item ids, slug groups to ids.
  const build = (): Framework => {
    const labels = Array.from(new Set(items.map((it) => it.group.trim() || "General")));
    const groups = labels.map((l) => ({ id: slug(l) || "general", name: l }));
    return {
      id: framework?.id ?? "",
      name: name.trim(),
      short: short.trim() || name.trim(),
      desc: desc.trim(),
      groups,
      items: items.map((it, idx) => ({
        id: `I${idx + 1}`,
        name: it.name.trim() || `Item ${idx + 1}`,
        group: slug(it.group.trim() || "General") || "general",
        mitre: it.mitre,
        ot: it.ot,
        class: it.class,
      })),
    };
  };

  const save = async () => {
    setBusy(true);
    setError(null);
    const doc = build();
    try {
      if (framework) await updateFramework(doc);
      else await createFramework(doc);
      onClose(true);
    } catch (e) {
      setError(String(e));
      setBusy(false);
    }
  };

  const remove = async () => {
    if (!framework || !confirm(`Delete custom framework "${framework.name}"?`)) return;
    setBusy(true);
    try {
      await deleteFramework(framework.id);
      onClose(true);
    } catch (e) {
      setError(String(e));
      setBusy(false);
    }
  };

  const valid = name.trim() !== "" && items.some((it) => it.mitre.length + it.ot.length + it.class.length > 0);

  return (
    <Modal title={framework ? "Edit custom framework" : "New custom framework"} onClose={() => onClose(false)}>
      <label>
        Name
        <input value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. Acme Control Mapping" autoFocus />
      </label>
      <div className="cond-row">
        <label className="grow">
          Short label
          <input value={short} onChange={(e) => setShort(e.target.value)} placeholder="sidebar label" />
        </label>
        <label className="grow">
          Description
          <input value={desc} onChange={(e) => setDesc(e.target.value)} placeholder="one line" />
        </label>
      </div>

      <label>Items — each cell maps to the codes / device classes it covers</label>
      {items.map((it, i) => (
        <div className="fw-item" key={i}>
          <div className="cond-row">
            <input
              className="grow"
              value={it.name}
              onChange={(e) => patchItem(i, { name: e.target.value })}
              placeholder="control / category name"
            />
            <input
              value={it.group}
              onChange={(e) => patchItem(i, { group: e.target.value })}
              placeholder="group / column"
            />
            <button type="button" className="linkish" title="Remove item" onClick={() => setItems(items.filter((_, j) => j !== i))}>
              <Icon name="delete" size={14} />
            </button>
          </div>
          <div className="fw-codes">
            <CodeChips codes={it.mitre} options={mitreOpts} label="+ ATT&CK" onChange={(mitre) => patchItem(i, { mitre })} />
            <CodeChips codes={it.ot} options={otOpts} label="+ OT" onChange={(ot) => patchItem(i, { ot })} />
            <CodeChips codes={it.class} options={classOpts} label="+ class" onChange={(cls) => patchItem(i, { class: cls })} />
          </div>
        </div>
      ))}
      <button
        type="button"
        className="linkish"
        onClick={() => setItems([...items, { name: "", group: "General", mitre: [], ot: [], class: [] }])}
      >
        <Icon name="add" size={14} /> item
      </button>

      {error && <div className="error">{error}</div>}
      <div className="modal-foot">
        {framework && (
          <button className="danger" disabled={busy} onClick={() => void remove()}>
            Delete
          </button>
        )}
        <button className="primary" disabled={busy || !valid} onClick={() => void save()}>
          Save
        </button>
      </div>
    </Modal>
  );
}
