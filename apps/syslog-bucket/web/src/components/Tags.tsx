import { useState } from "react";
import type { Tag } from "./../types";

export function TagChip({ tag, onRemove }: { tag: Tag; onRemove?: () => void }) {
  return (
    <span className="tagchip" style={{ borderColor: tag.color, color: tag.color }}>
      {tag.name}
      {onRemove && (
        <button
          title="Remove tag"
          onClick={(e) => {
            e.stopPropagation();
            onRemove();
          }}
        >
          ×
        </button>
      )}
    </span>
  );
}

// TagPicker is the "add label" dropdown in the detail pane.
export function TagPicker({ tags, exclude, onPick }: { tags: Tag[]; exclude: number[]; onPick: (id: number) => void }) {
  const [open, setOpen] = useState(false);
  const available = tags.filter((t) => !exclude.includes(t.id));
  if (available.length === 0) return null;
  return (
    <span className="tagpicker">
      <button className="linkish" onClick={() => setOpen(!open)}>
        + tag
      </button>
      {open && (
        <div className="tagpicker-menu">
          {available.map((t) => (
            <button
              key={t.id}
              onClick={() => {
                setOpen(false);
                onPick(t.id);
              }}
            >
              <TagChip tag={t} />
            </button>
          ))}
        </div>
      )}
    </span>
  );
}
