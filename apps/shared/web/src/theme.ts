// Dark/light theme, persisted per-browser in localStorage and applied to the
// <html data-theme> attribute; the stylesheet's :root[data-theme="light"] block
// supplies the light palette. One copy for the whole suite; each app's main.tsx
// imports it from here.
export type Theme = "dark" | "light";

const KEY = "yard-theme";

export function getTheme(): Theme {
  // Storage access can throw (blocked site data, some private modes); this
  // runs before first render, so it must never take the app down.
  try {
    return localStorage.getItem(KEY) === "light" ? "light" : "dark";
  } catch {
    return document.documentElement.dataset.theme === "light" ? "light" : "dark";
  }
}

export function applyTheme(t: Theme): void {
  document.documentElement.dataset.theme = t;
  try {
    localStorage.setItem(KEY, t);
  } catch {
    /* private mode: the theme just won't persist */
  }
}

export function toggleTheme(): Theme {
  const next: Theme = getTheme() === "dark" ? "light" : "dark";
  applyTheme(next);
  return next;
}

// Apply the saved theme once, before first render, to avoid a flash of dark.
// tool selects that tool's accent hue (tokens.css :root[data-tool]).
export function initTheme(tool?: "hose" | "valve" | "bucket"): void {
  if (tool) document.documentElement.dataset.tool = tool;
  applyTheme(getTheme());
}
