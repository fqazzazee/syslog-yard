import { useState } from "react";
import { createTag, deleteTag, updateTag } from "./../api";
import type { Tag } from "./../types";
import Modal from "./Modal";

const PALETTE = ["#ff4d4d", "#ffa726", "#ffd54f", "#6ee07a", "#4da3ff", "#b388ff", "#f06292", "#8a94a6"];

interface Props {
  tags: Tag[];
  onClose: (changed: boolean) => void;
}

export default function TagsModal({ tags, onClose }: Props) {
  const [drafts, setDrafts] = useState<Tag[]>(tags);
  const [newName, setNewName] = useState("");
  const [newColor, setNewColor] = useState(PALETTE[4]);
  const [error, setError] = useState<string | null>(null);
  const [changed, setChanged] = useState(false);

  const run = async (op: () => Promise<unknown>) => {
    setError(null);
    try {
      await op();
      setChanged(true);
      return true;
    } catch (e) {
      setError(String(e));
      return false;
    }
  };

  const add = async () => {
    const ok = await run(async () => {
      const t = await createTag({ name: newName.trim(), color: newColor, description: "" });
      setDrafts((d) => [...d, t]);
    });
    if (ok) setNewName("");
  };

  return (
    <Modal title="Tags" onClose={() => onClose(changed)}>
      {drafts.map((t, i) => (
        <div className="cond-row" key={t.id}>
          <input
            type="color"
            value={t.color}
            onChange={(e) => setDrafts(drafts.map((d, j) => (j === i ? { ...d, color: e.target.value } : d)))}
            onBlur={() => void run(() => updateTag(drafts[i]))}
          />
          <input
            className="cond-value"
            value={t.name}
            onChange={(e) => setDrafts(drafts.map((d, j) => (j === i ? { ...d, name: e.target.value } : d)))}
            onBlur={() => void run(() => updateTag(drafts[i]))}
          />
          <button
            type="button"
            className="linkish"
            title="Delete tag"
            onClick={() => {
              if (!confirm(`Delete tag "${t.name}"? It is removed from all entries.`)) return;
              void run(async () => {
                await deleteTag(t.id);
                setDrafts((d) => d.filter((x) => x.id !== t.id));
              });
            }}
          >
            ✕
          </button>
        </div>
      ))}

      <div className="cond-row">
        <select value={newColor} onChange={(e) => setNewColor(e.target.value)} style={{ color: newColor }}>
          {PALETTE.map((c) => (
            <option key={c} value={c} style={{ color: c }}>
              ⬤
            </option>
          ))}
        </select>
        <input
          className="cond-value"
          placeholder="new tag name"
          value={newName}
          onChange={(e) => setNewName(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && newName.trim() && void add()}
        />
        <button type="button" className="primary" disabled={!newName.trim()} onClick={() => void add()}>
          Add
        </button>
      </div>

      {error && <div className="error">{error}</div>}
    </Modal>
  );
}
