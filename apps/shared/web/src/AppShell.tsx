// AppShell is the one frame around every yard tool, so hose, valve and
// bucket read as a single product even though each is its own SPA on its
// own port:
//
//   top bar   menu toggle · syslog-yard brand · tool switcher · theme · help · account
//   side nav  every tool with its sections; the current tool's sections are
//             in-app hash links, the other tools' are deep links to their URL
//             (from /api/hints). Collapses to an icon rail on wide screens and
//             becomes a modal overlay drawer on narrow ones.
//   main      the tool's page (landmark target of the skip link)
import { useEffect, useRef, useState, type ReactNode } from "react";
import { About } from "./About";
import { AccountMenu } from "./AccountMenu";
import { focusables, useModalKeys } from "./Dialog";
import { useMediaQuery, useStoredState } from "./hooks";
import { Icon } from "./Icon";
import type { MenuItem } from "./Menu";
import { TOOLS, toolDef, toolHref, type ToolId } from "./suite";
import { getTheme, toggleTheme, type Theme } from "./theme";
import { Toaster } from "./Toast";
import { IconButton, cx } from "./ui";
import type { AuthUser } from "./yardAuthApi";

const NARROW = "(max-width: 899px)";

export interface AppShellProps {
  tool: ToolId;
  links: Record<string, string>; // /api/hints
  section: string; // current section id (highlighted in the nav)
  title: string; // page title, for document.title
  user: AuthUser | null;
  onSignOut: () => void;
  accountItems?: MenuItem[];
  usersDeleteNote?: string;
  // Extra content after a section's label in the current tool (counts…).
  sectionBadges?: Record<string, ReactNode>;
  // A richer navigation for the current tool, shown instead of its plain
  // section list while the nav is expanded (bucket: buckets, tags, rules…).
  navContent?: ReactNode;
  // Theme changes, for components that need it in JS (valve's canvas).
  onThemeChange?: (t: Theme) => void;
  children: ReactNode;
}

export function AppShell(props: AppShellProps) {
  const { tool, links, section, title, user } = props;
  const narrow = useMediaQuery(NARROW);
  const [mode, setMode] = useStoredState<"full" | "rail">(`yard-nav:${tool}`, tool === "valve" ? "rail" : "full");
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [aboutOpen, setAboutOpen] = useState(false);
  const [theme, setTheme] = useState<Theme>(getTheme());
  const navRef = useRef<HTMLElement>(null);
  const toggleRef = useRef<HTMLButtonElement>(null);
  const current = toolDef(tool);

  useEffect(() => {
    document.title = `${title} · ${current.name}`;
  }, [title, current.name]);

  // Leaving narrow mode closes the drawer.
  useEffect(() => {
    if (!narrow) setDrawerOpen(false);
  }, [narrow]);

  // The drawer is a modal overlay: focus moves in, Tab stays inside (the
  // same trap as Dialog), Escape closes it and focus goes back to the toggle.
  const drawerModal = narrow && drawerOpen;
  useEffect(() => {
    if (!drawerModal) return;
    const nav = navRef.current;
    if (nav) focusables(nav)[0]?.focus();
  }, [drawerModal]);
  useModalKeys(navRef, drawerModal, () => {
    setDrawerOpen(false);
    toggleRef.current?.focus();
  });

  const rail = !narrow && mode === "rail";
  const expanded = narrow ? drawerOpen : !rail;
  const toggleNav = () => (narrow ? setDrawerOpen(!drawerOpen) : setMode(rail ? "full" : "rail"));
  const toggleLabel = narrow
    ? drawerOpen
      ? "Close navigation"
      : "Open navigation"
    : rail
      ? "Expand navigation"
      : "Collapse navigation";

  const visibleTools = TOOLS.filter((t) => t.id === tool || toolHref(tool, links, t.id) !== null);
  const suite = visibleTools.length > 1;

  return (
    <div className={cx("yard-shell", rail && "nav-rail", narrow && "nav-narrow", drawerOpen && "drawer-open")}>
      <a className="skip-link" href="#yard-main" onClick={(e) => {
        e.preventDefault();
        document.getElementById("yard-main")?.focus();
      }}>
        Skip to content
      </a>
      <header className="yard-topbar">
        <button
          ref={toggleRef}
          type="button"
          className="icon-btn quiet nav-toggle"
          aria-label={toggleLabel}
          title={toggleLabel}
          aria-expanded={expanded}
          aria-controls="yard-sidenav"
          onClick={toggleNav}
        >
          <Icon name={narrow ? "menu" : rail ? "left_panel_open" : "left_panel_close"} size={20} />
        </button>
        <a className="yard-brand" href="#/" title={`${current.name} home`}>
          <Icon name="yard" size={22} />
          <span className="yard-brand-text">
            syslog-<b>yard</b>
          </span>
        </a>
        {suite && (
          <nav className="yard-switcher" aria-label="Tools">
            {visibleTools.map((t) => {
              const href = toolHref(tool, links, t.id)!;
              return (
                <a
                  key={t.id}
                  href={t.id === tool ? "#/" : href}
                  className={cx("yard-tool", t.id === tool && "current")}
                  data-tool={t.id}
                  aria-current={t.id === tool ? "page" : undefined}
                  title={`${t.name} — ${t.tagline}`}
                >
                  <Icon name={t.icon} size={17} />
                  <span className="yard-tool-label">{t.label}</span>
                </a>
              );
            })}
          </nav>
        )}
        {!suite && (
          <span className="yard-tool current solo" data-tool={tool}>
            <Icon name={current.icon} size={17} />
            <span className="yard-tool-label">{current.label}</span>
          </span>
        )}
        <div className="yard-topbar-spacer" />
        <IconButton
          icon={theme === "dark" ? "light_mode" : "dark_mode"}
          label={`Switch to ${theme === "dark" ? "light" : "dark"} theme`}
          onClick={() => {
            const t = toggleTheme();
            setTheme(t);
            props.onThemeChange?.(t);
          }}
        />
        <IconButton icon="help" label="About & help" onClick={() => setAboutOpen(true)} />
        {user && (
          <AccountMenu
            user={user}
            onSignOut={props.onSignOut}
            extraItems={props.accountItems}
            usersDeleteNote={props.usersDeleteNote}
          />
        )}
      </header>

      <div className="yard-body">
        <nav
          id="yard-sidenav"
          ref={navRef}
          className="yard-sidenav"
          aria-label="syslog-yard navigation"
          role={drawerModal ? "dialog" : undefined}
          aria-modal={drawerModal ? true : undefined}
          tabIndex={drawerModal ? -1 : undefined}
          onClick={(e) => {
            // Following a link closes the drawer.
            if (narrow && (e.target as HTMLElement).closest("a")) setDrawerOpen(false);
          }}
        >
          {visibleTools.map((t) => {
            const isCurrent = t.id === tool;
            const headHref = toolHref(tool, links, t.id)!;
            return (
              <div key={t.id} className={cx("nav-group", isCurrent && "current")} data-tool={t.id}>
                <a
                  className="nav-group-head"
                  href={headHref}
                  title={`${t.name} — ${t.tagline}`}
                  aria-label={rail ? t.name : undefined}
                >
                  <Icon name={t.icon} size={18} />
                  <span className="nav-text">
                    <span className="nav-group-name">{t.name}</span>
                    <span className="nav-group-tag">{t.tagline}</span>
                  </span>
                </a>
                {isCurrent && props.navContent && !rail ? (
                  <div className="nav-rich">{props.navContent}</div>
                ) : (
                  (isCurrent || !rail) && (
                    <ul className="nav-list">
                      {t.sections.map((s) => {
                        const active = isCurrent && s.id === section;
                        return (
                          <li key={s.id}>
                            <a
                              className={cx("nav-link", active && "active")}
                              href={toolHref(tool, links, t.id, s.id)!}
                              aria-current={active ? "page" : undefined}
                              title={isCurrent ? s.label : `${s.label} — ${t.name}`}
                            >
                              <Icon name={s.icon} size={17} />
                              <span className="nav-text">{s.label}</span>
                              {isCurrent && props.sectionBadges?.[s.id]}
                            </a>
                          </li>
                        );
                      })}
                    </ul>
                  )
                )}
              </div>
            );
          })}
        </nav>
        {drawerOpen && <div className="yard-scrim" onClick={() => setDrawerOpen(false)} aria-hidden="true" />}
        <main id="yard-main" className="yard-main" tabIndex={-1}>
          {props.children}
        </main>
      </div>
      {aboutOpen && <About tool={tool} onClose={() => setAboutOpen(false)} />}
      <Toaster />
    </div>
  );
}
