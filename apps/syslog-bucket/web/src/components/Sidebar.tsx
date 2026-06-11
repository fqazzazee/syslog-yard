import type { Bucket, Channel, Rule, Selection, Tag, User } from "./../types";
import { Icon } from "./Icon";
import { TagChip } from "./Tags";

interface Props {
  buckets: Bucket[];
  tags: Tag[];
  rules: Rule[];
  channels: Channel[];
  selection: Selection;
  me: User;
  readOnly: boolean; // viewer role: no create/edit affordances
  onSelect: (sel: Selection) => void;
  onEditBucket: (b: Bucket | null) => void; // null = new
  onEditRule: (r: Rule | null) => void;
  onManageTags: () => void;
  onManageChannels: () => void;
}

export default function Sidebar({
  buckets,
  tags,
  rules,
  channels,
  selection,
  me,
  readOnly,
  onSelect,
  onEditBucket,
  onEditRule,
  onManageTags,
  onManageChannels,
}: Props) {
  const isAll = selection.kind === "all";
  const isMitre = selection.kind === "mitre" || selection.kind === "technique";
  return (
    <nav className="sidebar">
      <button className={`nav-item${isAll ? " active" : ""}`} onClick={() => onSelect({ kind: "all" })}>
        <Icon name="description" size={16} /> All Logs
      </button>
      <button className={`nav-item${isMitre ? " active" : ""}`} onClick={() => onSelect({ kind: "mitre" })}>
        <Icon name="crisis_alert" size={16} /> ATT&CK matrix
      </button>

      <div className="nav-section">
        <span>Buckets</span>
        {!readOnly && (
          <button className="linkish" title="New bucket" onClick={() => onEditBucket(null)}>
            <Icon name="add" size={15} />
          </button>
        )}
      </div>
      {buckets.map((b) => {
        const active = selection.kind === "bucket" && selection.id === b.id;
        const foreign = b.owner_id !== undefined && b.owner_id !== me.id;
        return (
          <div key={b.id} className={`nav-item${active ? " active" : ""}`}>
            <button
              className="nav-label"
              title={foreign && b.owner_name ? `Shared by ${b.owner_name}` : b.description || undefined}
              onClick={() => onSelect({ kind: "bucket", id: b.id })}
            >
              <Icon name="folder" size={15} /> {b.name}
              {b.shared && b.owner_id === me.id && (
                <span className="share-mark" title="Shared with others">
                  <Icon name="share" size={12} />
                </span>
              )}
              {foreign && b.owner_name && <span className="owner-mark">· {b.owner_name}</span>}
            </button>
            {b.can_edit && (
              <button className="nav-edit" title="Edit bucket" onClick={() => onEditBucket(b)}>
                <Icon name="edit" size={14} />
              </button>
            )}
          </div>
        );
      })}
      {buckets.length === 0 && <p className="nav-empty">Saved searches appear here.</p>}

      <div className="nav-section">
        <span>Tags</span>
        {!readOnly && (
          <button className="linkish" title="Manage tags" onClick={onManageTags}>
            <Icon name="add" size={15} />
          </button>
        )}
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
        {!readOnly && (
          <button className="linkish" title="New rule" onClick={() => onEditRule(null)}>
            <Icon name="add" size={15} />
          </button>
        )}
      </div>
      {rules.map((r) => (
        <div key={r.id} className="nav-item">
          <button
            className={`nav-label${r.enabled ? "" : " disabled"}`}
            disabled={readOnly}
            onClick={() => !readOnly && onEditRule(r)}
          >
            <Icon name="rule" size={15} /> {r.name}
          </button>
        </div>
      ))}

      {!readOnly && (
        <>
          <div className="nav-section">
            <span>Notifications</span>
            <button className="linkish" title="Manage channels" onClick={onManageChannels}>
              <Icon name="add" size={15} />
            </button>
          </div>
          {channels.map((c) => (
            <div key={c.id} className="nav-item">
              <button className={`nav-label${c.enabled ? "" : " disabled"}`} onClick={onManageChannels}>
                <Icon name="notifications" size={15} /> {c.name}
              </button>
            </div>
          ))}
          {channels.length === 0 && <p className="nav-empty">Webhook / Slack / email destinations.</p>}
        </>
      )}
    </nav>
  );
}
