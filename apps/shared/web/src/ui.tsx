// Shared UI primitives for the yard SPAs. Styles live in components.css and
// build on tokens.css. Plain <button>s pick up the same base look, so these
// components mostly pin down structure and accessibility.
import {
  cloneElement,
  isValidElement,
  useId,
  useRef,
  type ButtonHTMLAttributes,
  type KeyboardEvent,
  type ReactElement,
  type ReactNode,
} from "react";
import { Icon, type IconName } from "./Icon";

export function cx(...parts: (string | false | null | undefined)[]): string {
  return parts.filter(Boolean).join(" ");
}

// --- buttons ----------------------------------------------------------------

export type ButtonVariant = "default" | "primary" | "danger" | "quiet" | "link";

const VARIANT_CLASS: Record<ButtonVariant, string | undefined> = {
  default: undefined,
  primary: "primary",
  danger: "danger",
  quiet: "quiet",
  link: "linkish",
};

export interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant;
  icon?: IconName;
  size?: "sm" | "md";
}

export function Button({ variant = "default", icon, size = "md", className, children, type, ...rest }: ButtonProps) {
  return (
    <button
      type={type ?? "button"}
      className={cx(VARIANT_CLASS[variant], size === "sm" && "btn-sm", className)}
      {...rest}
    >
      {icon && <Icon name={icon} size={size === "sm" ? 14 : 16} />}
      {children}
    </button>
  );
}

// IconButton is an icon-only button; label is required and becomes its
// accessible name (and hover tooltip).
export function IconButton({
  icon,
  label,
  iconSize = 18,
  variant = "quiet",
  className,
  title,
  type,
  ...rest
}: Omit<ButtonProps, "children" | "icon" | "size"> & { icon: IconName; label: string; iconSize?: number }) {
  return (
    <button
      type={type ?? "button"}
      aria-label={label}
      title={title ?? label}
      className={cx("icon-btn", VARIANT_CLASS[variant], className)}
      {...rest}
    >
      <Icon name={icon} size={iconSize} />
    </button>
  );
}

// --- form fields --------------------------------------------------------------

// Field labels one control and wires its help and error text through
// aria-describedby / aria-invalid. inline puts a checkbox before its label.
export function Field({
  label,
  help,
  error,
  inline,
  className,
  children,
}: {
  label: ReactNode;
  help?: ReactNode;
  error?: ReactNode;
  inline?: boolean;
  className?: string;
  children: ReactElement;
}) {
  const id = useId();
  const childProps = (isValidElement(children) ? children.props : {}) as { id?: string };
  const controlId = childProps.id ?? `${id}-control`;
  const helpId = help ? `${id}-help` : undefined;
  const errId = error ? `${id}-err` : undefined;
  const describedBy = [helpId, errId].filter(Boolean).join(" ") || undefined;
  const control = isValidElement(children)
    ? cloneElement(children as ReactElement<Record<string, unknown>>, {
        id: controlId,
        "aria-describedby": describedBy,
        "aria-invalid": error ? true : undefined,
      })
    : children;
  if (inline) {
    return (
      <div className={cx("field field-inline", className)}>
        <label htmlFor={controlId}>
          {control}
          <span>{label}</span>
        </label>
        {help && (
          <p className="field-help" id={helpId}>
            {help}
          </p>
        )}
        {error && (
          <p className="field-error" id={errId}>
            {error}
          </p>
        )}
      </div>
    );
  }
  return (
    <div className={cx("field", className)}>
      <label className="field-label" htmlFor={controlId}>
        {label}
      </label>
      {control}
      {help && (
        <p className="field-help" id={helpId}>
          {help}
        </p>
      )}
      {error && (
        <p className="field-error" id={errId}>
          {error}
        </p>
      )}
    </div>
  );
}

// --- banners --------------------------------------------------------------------

export type Tone = "error" | "success" | "warning" | "info";

const TONE_ICON: Record<Tone, IconName> = {
  error: "error",
  success: "check_circle",
  warning: "warning",
  info: "info",
};

// Banner is the one inline message: page-level errors, form errors and
// notices alike. Errors are announced assertively (role=alert).
export function Banner({
  kind = "error",
  children,
  onDismiss,
  className,
}: {
  kind?: Tone;
  children: ReactNode;
  onDismiss?: () => void;
  className?: string;
}) {
  return (
    <div className={cx("banner", `banner-${kind}`, className)} role={kind === "error" ? "alert" : "status"}>
      <Icon name={TONE_ICON[kind]} size={16} className="banner-icon" />
      <div className="banner-body">{children}</div>
      {onDismiss && <IconButton icon="close" label="Dismiss" iconSize={16} onClick={onDismiss} />}
    </div>
  );
}

// --- empty / loading states -------------------------------------------------------

export function EmptyState({
  icon,
  title,
  children,
  className,
}: {
  icon?: IconName;
  title: ReactNode;
  children?: ReactNode;
  className?: string;
}) {
  return (
    <div className={cx("empty-state", className)}>
      {icon && <Icon name={icon} size={28} className="empty-icon" />}
      <p className="empty-title">{title}</p>
      {children && <div className="empty-body">{children}</div>}
    </div>
  );
}

export function Loading({ label = "Loading…", className }: { label?: string; className?: string }) {
  return (
    <div className={cx("loading", className)} role="status">
      <span className="spinner" aria-hidden="true" />
      {label}
    </div>
  );
}

// --- badges -------------------------------------------------------------------------

export function Badge({
  tone = "neutral",
  children,
  className,
  title,
}: {
  tone?: "neutral" | "accent" | "success" | "warning" | "danger";
  children: ReactNode;
  className?: string;
  title?: string;
}) {
  return (
    <span className={cx("ybadge", `ybadge-${tone}`, className)} title={title}>
      {children}
    </span>
  );
}

// --- page header --------------------------------------------------------------------

// PageHeader is the title row of a section: the page's h1, optional meta
// (counts, status) and its actions, which wrap on narrow screens.
export function PageHeader({
  title,
  icon,
  meta,
  actions,
  className,
}: {
  title: ReactNode;
  icon?: IconName;
  meta?: ReactNode;
  actions?: ReactNode;
  className?: string;
}) {
  return (
    <div className={cx("page-header", className)}>
      <h1 className="page-title">
        {icon && <Icon name={icon} size={20} />}
        {title}
      </h1>
      {meta && <div className="page-meta">{meta}</div>}
      {actions && <div className="page-actions">{actions}</div>}
    </div>
  );
}

// --- tabs -----------------------------------------------------------------------------

export interface TabDef<T extends string> {
  id: T;
  label: ReactNode;
  icon?: IconName;
}

// Tabs is a WAI-ARIA tablist with automatic activation: arrow keys,
// Home/End move between tabs. Pair each tab with a <TabPanel>.
export function Tabs<T extends string>({
  tabs,
  value,
  onChange,
  label,
  idBase,
}: {
  tabs: TabDef<T>[];
  value: T;
  onChange: (id: T) => void;
  label: string;
  idBase: string;
}) {
  const ref = useRef<HTMLDivElement>(null);
  const onKey = (e: KeyboardEvent<HTMLDivElement>) => {
    const i = tabs.findIndex((t) => t.id === value);
    let next = -1;
    if (e.key === "ArrowRight") next = (i + 1) % tabs.length;
    else if (e.key === "ArrowLeft") next = (i - 1 + tabs.length) % tabs.length;
    else if (e.key === "Home") next = 0;
    else if (e.key === "End") next = tabs.length - 1;
    if (next < 0) return;
    e.preventDefault();
    onChange(tabs[next].id);
    ref.current?.querySelectorAll<HTMLButtonElement>('[role="tab"]')[next]?.focus();
  };
  return (
    <div className="tabs" role="tablist" aria-label={label} ref={ref} onKeyDown={onKey}>
      {tabs.map((t) => (
        <button
          key={t.id}
          type="button"
          role="tab"
          id={`${idBase}-tab-${t.id}`}
          aria-selected={t.id === value}
          aria-controls={`${idBase}-panel-${t.id}`}
          tabIndex={t.id === value ? 0 : -1}
          className={cx("tab", t.id === value && "active")}
          onClick={() => onChange(t.id)}
        >
          {t.icon && <Icon name={t.icon} size={16} />}
          {t.label}
        </button>
      ))}
    </div>
  );
}

export function TabPanel({
  idBase,
  id,
  children,
  className,
}: {
  idBase: string;
  id: string;
  children: ReactNode;
  className?: string;
}) {
  return (
    <div
      role="tabpanel"
      id={`${idBase}-panel-${id}`}
      aria-labelledby={`${idBase}-tab-${id}`}
      tabIndex={0}
      className={cx("tabpanel", className)}
    >
      {children}
    </div>
  );
}
