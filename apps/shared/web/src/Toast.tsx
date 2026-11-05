// Toasts: short-lived confirmations ("Applied", "Saved") that don't need a
// place on the page. toast() can be called from anywhere; the app shell
// renders the <Toaster/> live region once. Errors that need attention stay
// on the page as a <Banner> instead.
import { useSyncExternalStore } from "react";
import { Icon } from "./Icon";
import { IconButton, type Tone } from "./ui";

interface ToastItem {
  id: number;
  text: string;
  kind: Tone;
}

let items: ToastItem[] = [];
let nextId = 0;
const listeners = new Set<() => void>();
const emit = () => listeners.forEach((l) => l());

export function dismissToast(id: number): void {
  items = items.filter((t) => t.id !== id);
  emit();
}

export function toast(text: string, kind: Tone = "success"): void {
  const id = ++nextId;
  items = [...items.slice(-3), { id, text, kind }];
  emit();
  window.setTimeout(() => dismissToast(id), kind === "error" || kind === "warning" ? 8000 : 4000);
}

function subscribe(l: () => void) {
  listeners.add(l);
  return () => {
    listeners.delete(l);
  };
}

const ICONS = { success: "check_circle", error: "error", warning: "warning", info: "info" } as const;

export function Toaster() {
  const list = useSyncExternalStore(subscribe, () => items);
  return (
    <div className="toaster" aria-live="polite" aria-relevant="additions">
      {list.map((t) => (
        <div key={t.id} className={`toast toast-${t.kind}`} role={t.kind === "error" ? "alert" : "status"}>
          <Icon name={ICONS[t.kind]} size={16} />
          <span className="toast-text">{t.text}</span>
          <IconButton icon="close" label="Dismiss" iconSize={16} onClick={() => dismissToast(t.id)} />
        </div>
      ))}
    </div>
  );
}
