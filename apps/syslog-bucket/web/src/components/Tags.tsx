import { useState } from "react";
import type { Tag } from "./../types";

export function TagChip({ tag, disabled, onRemove }: { tag: Tag; disabled?: boolean; onRemove?: () => void }) {
  return (
    <span className="tagchip" style={{ borderColor: tag.color, color: tag.color }}>
      {tag.name}
      {onRemove && (
        <button
          type="button"
          title="Remove tag"
          aria-label={`Remove tag ${tag.name}`}
          disabled={disabled}
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
export function TagPicker({
  tags,
  exclude,
  disabled,
  onPick,
}: {
  tags: Tag[];
  exclude: number[];
  disabled?: boolean;
  onPick: (id: number) => void;
}) {
  const [open, setOpen] = useState(false);
  const available = tags.filter((t) => !exclude.includes(t.id));
  if (available.length === 0) return null;
  return (
    <span className="tagpicker">
      <button
        type="button"
        className="linkish"
        disabled={disabled}
        aria-expanded={open && !disabled}
        onClick={() => setOpen(!open)}
        onKeyDown={(e) => e.key === "Escape" && setOpen(false)}
      >
        + tag
      </button>
      {open && !disabled && (
        <div className="tagpicker-menu">
          {available.map((t) => (
            <button
              key={t.id}
              type="button"
              aria-label={`Add tag ${t.name}`}
              onKeyDown={(e) => e.key === "Escape" && setOpen(false)}
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
