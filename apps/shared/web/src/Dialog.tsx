// Dialog is the one modal for the whole suite: role=dialog + aria-modal,
// labelled by its title, focus moved in on open (to an [autofocus] /
// [data-autofocus] control, else the first field, else the panel), Tab
// trapped inside, Escape closes, focus returns to whatever opened it, and the
// backdrop closes it only when a mousedown starts on the backdrop itself (a
// text selection that starts in a field and ends outside must not close it).
// Stacked dialogs work: only the topmost reacts to keys.
import { useEffect, useId, useRef, useState, type ReactNode } from "react";
import { createPortal } from "react-dom";
import { IconButton } from "./ui";

const stack: symbol[] = [];
let scrollLocks = 0;

const FOCUSABLE =
  'a[href], area[href], button:not([disabled]), input:not([disabled]):not([type="hidden"]), select:not([disabled]), textarea:not([disabled]), iframe, [tabindex]:not([tabindex="-1"]), [contenteditable="true"]';

export function focusables(root: HTMLElement): HTMLElement[] {
  return Array.from(root.querySelectorAll<HTMLElement>(FOCUSABLE)).filter(
    (el) => !el.closest("[inert]") && el.getClientRects().length > 0,
  );
}

export interface DialogProps {
  title: ReactNode;
  onClose: () => void;
  children: ReactNode;
  // Buttons row at the bottom (right-aligned).
  footer?: ReactNode;
  size?: "sm" | "md" | "lg";
  className?: string;
  // Optional element shown before the title (e.g. an icon).
  titleIcon?: ReactNode;
}

export function Dialog({ title, onClose, children, footer, size = "md", className, titleIcon }: DialogProps) {
  const titleId = useId();
  const panelRef = useRef<HTMLDivElement>(null);
  const bodyRef = useRef<HTMLDivElement>(null);
  // Captured during render, before any [autoFocus] child grabs focus.
  const [returnTo] = useState(() => document.activeElement as HTMLElement | null);
  const onCloseRef = useRef(onClose);
  onCloseRef.current = onClose;

  useEffect(() => {
    const token = Symbol("dialog");
    stack.push(token);
    const panel = panelRef.current!;
    if (!panel.contains(document.activeElement)) {
      const auto = panel.querySelector<HTMLElement>("[autofocus], [data-autofocus]");
      const first = bodyRef.current ? focusables(bodyRef.current)[0] : undefined;
      (auto ?? first ?? panel).focus();
    }
    if (scrollLocks++ === 0) document.documentElement.classList.add("dialog-open");

    const onKey = (e: KeyboardEvent) => {
      if (stack[stack.length - 1] !== token) return;
      if (e.key === "Escape") {
        e.preventDefault();
        e.stopPropagation();
        onCloseRef.current();
      } else if (e.key === "Tab") {
        const items = focusables(panel);
        if (items.length === 0) {
          e.preventDefault();
          panel.focus();
          return;
        }
        const first = items[0];
        const last = items[items.length - 1];
        const active = document.activeElement;
        if (e.shiftKey && (active === first || !panel.contains(active))) {
          e.preventDefault();
          last.focus();
        } else if (!e.shiftKey && (active === last || !panel.contains(active))) {
          e.preventDefault();
          first.focus();
        }
      }
    };
    document.addEventListener("keydown", onKey, true);
    return () => {
      document.removeEventListener("keydown", onKey, true);
      const i = stack.indexOf(token);
      if (i >= 0) stack.splice(i, 1);
      if (--scrollLocks === 0) document.documentElement.classList.remove("dialog-open");
      if (returnTo && returnTo.isConnected) returnTo.focus();
    };
  }, [returnTo]);

  return createPortal(
    <div className="dialog-backdrop" onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
      <div
        ref={panelRef}
        className={`dialog dialog-${size}${className ? ` ${className}` : ""}`}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        tabIndex={-1}
      >
        <div className="dialog-head">
          <h2 id={titleId}>
            {titleIcon}
            {title}
          </h2>
          <IconButton icon="close" label="Close" onClick={onClose} />
        </div>
        <div className="dialog-body" ref={bodyRef}>
          {children}
        </div>
        {footer && <div className="dialog-actions">{footer}</div>}
      </div>
    </div>,
    document.body,
  );
}
