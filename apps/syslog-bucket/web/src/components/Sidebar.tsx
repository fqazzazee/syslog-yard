import type { Bucket, Rule, Selection, Tag } from "./../types";
import { TagChip } from "./Tags";

interface Props {
  buckets: Bucket[];
  tags: Tag[];
  rules: Rule[];
  selection: Selection;
  onSelect: (sel: Selection) => void;
  onEditBucket: (b: Bucket | null) => void; // null = new
  onEditRule: (r: Rule | null) => void;
  onManageTags: () => void;
}

export default function Sidebar({
  buckets,
  tags,
  rules,
  selection,
  onSelect,
  onEditBucket,
  onEditRule,
  onManageTags,
}: Props) {
  const isAll = selection.kind === "all";
  return (
    <nav className="sidebar">
      <button className={`nav-item${isAll ? " active" : ""}`} onClick={() => onSelect({ kind: "all" })}>
        📥 All Logs
      </button>

      <div className="nav-section">
        <span>Buckets</span>
        <button className="linkish" title="New bucket" onClick={() => onEditBucket(null)}>
          ＋
        </button>
      </div>
      {buckets.map((b) => {
        const active = selection.kind === "bucket" && selection.id === b.id;
        return (
          <div key={b.id} className={`nav-item${active ? " active" : ""}`}>
            <button className="nav-label" onClick={() => onSelect({ kind: "bucket", id: b.id })}>
              🗂 {b.name}
            </button>
            <button className="nav-edit" title="Edit bucket" onClick={() => onEditBucket(b)}>
              ✎
            </button>
          </div>
        );
      })}
      {buckets.length === 0 && <p className="nav-empty">Saved searches appear here.</p>}

      <div className="nav-section">
        <span>Tags</span>
        <button className="linkish" title="Manage tags" onClick={onManageTags}>
          ＋
        </button>
      </div>
      <div className="nav-tags">
        {tags.map((t) => {
          const active = selection.kind === "tag" && selection.id === t.id;
          return (
            <button
              key={t.id}
              className={`nav-tag${active ? " active" : ""}`}
              onClick={() => onSelect({ kind: "tag", id: t.id })}
            >
              <TagChip tag={t} />
            </button>
          );
        })}
      </div>

      <div className="nav-section">
        <span>Rules</span>
        <button className="linkish" title="New rule" onClick={() => onEditRule(null)}>
          ＋
        </button>
      </div>
      {rules.map((r) => (
        <div key={r.id} className="nav-item">
          <button className={`nav-label${r.enabled ? "" : " disabled"}`} onClick={() => onEditRule(r)}>
            ⚙ {r.name}
          </button>
        </div>
      ))}
    </nav>
  );
}
