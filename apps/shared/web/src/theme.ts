// Dark/light theme, persisted per-browser in localStorage and applied to the
// <html data-theme> attribute; the stylesheet's :root[data-theme="light"] block
// supplies the light palette. One copy for the whole suite: the per-app theme.ts files are re-export shims.
export type Theme = "dark" | "light";

const KEY = "yard-theme";

export function getTheme(): Theme {
  return localStorage.getItem(KEY) === "light" ? "light" : "dark";
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
export function initTheme(): void {
  applyTheme(getTheme());
}
