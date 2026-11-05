// Menu is a button that opens a list of actions (WAI-ARIA menu button):
// arrow keys / Home / End move between items, Escape closes and returns
// focus to the button, a click outside or Tab closes it.
import { useEffect, useId, useRef, useState, type KeyboardEvent, type ReactNode } from "react";
import { Icon, type IconName } from "./Icon";
import { cx } from "./ui";

export interface MenuItem {
  id: string;
  label: ReactNode;
  icon?: IconName;
  onSelect: () => void;
  disabled?: boolean;
  title?: string;
}

export function Menu({
  trigger,
  label,
  items,
  className,
  triggerClassName,
  align = "end",
}: {
  trigger: ReactNode; // button content
  label?: string; // accessible name when the trigger has no text
  items: MenuItem[];
  className?: string;
  triggerClassName?: string;
  align?: "start" | "end";
}) {
  const [open, setOpen] = useState(false);
  const rootRef = useRef<HTMLDivElement>(null);
  const btnRef = useRef<HTMLButtonElement>(null);
  const listRef = useRef<HTMLDivElement>(null);
  const menuId = useId();

  const itemEls = () => Array.from(listRef.current?.querySelectorAll<HTMLButtonElement>('[role="menuitem"]:not(:disabled)') ?? []);

  useEffect(() => {
    if (!open) return;
    itemEls()[0]?.focus();
    const onDown = (e: MouseEvent) => {
      if (!rootRef.current?.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener("mousedown", onDown);
    return () => document.removeEventListener("mousedown", onDown);
  }, [open]);

  const close = (refocus: boolean) => {
    setOpen(false);
    if (refocus) btnRef.current?.focus();
  };

  const onListKey = (e: KeyboardEvent<HTMLDivElement>) => {
    const els = itemEls();
    const i = els.indexOf(document.activeElement as HTMLButtonElement);
    let next = -1;
    if (e.key === "ArrowDown") next = (i + 1) % els.length;
    else if (e.key === "ArrowUp") next = (i - 1 + els.length) % els.length;
    else if (e.key === "Home") next = 0;
    else if (e.key === "End") next = els.length - 1;
    else if (e.key === "Escape") {
      e.preventDefault();
      e.stopPropagation();
      close(true);
      return;
    } else if (e.key === "Tab") {
      setOpen(false);
      return;
    }
    if (next >= 0) {
      e.preventDefault();
      els[next]?.focus();
    }
  };

  return (
    <div className={cx("menu", className)} ref={rootRef}>
      <button
        ref={btnRef}
        type="button"
        className={cx("menu-trigger", open && "open", triggerClassName)}
        aria-haspopup="menu"
        aria-expanded={open}
        aria-controls={open ? menuId : undefined}
        aria-label={label}
        title={label}
        onClick={() => setOpen(!open)}
        onKeyDown={(e) => {
          if (e.key === "ArrowDown" && !open) {
            e.preventDefault();
            setOpen(true);
          }
        }}
      >
        {trigger}
      </button>
      {open && (
        <div
          className={cx("menu-list", align === "start" && "menu-start")}
          role="menu"
          id={menuId}
          ref={listRef}
          onKeyDown={onListKey}
        >
          {items.map((it) => (
            <button
              key={it.id}
              type="button"
              role="menuitem"
              tabIndex={-1}
              disabled={it.disabled}
              title={it.title}
              onClick={() => {
                close(true);
                it.onSelect();
              }}
            >
              {it.icon && <Icon name={it.icon} size={16} />}
              {it.label}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}
