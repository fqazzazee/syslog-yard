// The bucket's rich navigation, rendered inside the shared side nav (in
// place of the plain section list while the nav is expanded): views,
// frameworks, buckets, tags, rules and notification channels, each with its
// create/edit affordances. Views are hash links (see routes.ts).
//
// SidebarRail covers the collapsed icon rail, where the shell shows only the
// bucket's sections: it adds what no section reaches (tags, the tag manager,
// notification channels, and for admins the audit log).
import type { ReactNode } from "react";
import { Menu, type MenuItem } from "../../../../shared/web/src/Menu";
import { IconButton } from "../../../../shared/web/src/ui";
import { hrefFor, type Page } from "./../routes";
import type { Bucket, Channel, Framework, Rule, Selection, Tag, User } from "./../types";
import { Icon, type IconName } from "./Icon";
import { TagChip } from "./Tags";

interface Props {
  buckets: Bucket[];
  tags: Tag[];
  rules: Rule[];
  channels: Channel[];
  frameworks: Framework[];
  selection: Selection | null; // null while a list page is open
  page: Page | null;
  me: User;
  readOnly: boolean; // viewer role: no create/edit affordances
  onEditBucket: (b: Bucket | null) => void; // null = new
  onEditRule: (r: Rule | null) => void; // a read-only view for viewers
  onEditFramework: (f: Framework | null) => void; // null = new custom framework
  onManageTags: () => void;
  onManageChannels: () => void;
}

function NavLink({
  href,
  icon,
  active,
  title,
  className,
  children,
}: {
  href: string;
  icon: IconName;
  active: boolean;
  title?: string;
  className?: string;
  children: ReactNode;
}) {
  return (
    <a
      href={href}
      className={`nav-link${active ? " active" : ""}${className ? ` ${className}` : ""}`}
      aria-current={active ? "page" : undefined}
      title={title}
    >
      <Icon name={icon} size={16} />
      <span className="nav-text">{children}</span>
    </a>
  );
}

function SubHead({ label, href, active, action }: { label: string; href?: string; active?: boolean; action?: ReactNode }) {
  return (
    <div className="nav-subhead">
      {href ? (
        <a href={href} aria-current={active ? "page" : undefined} className={active ? "active" : undefined}>
          {label}
        </a>
      ) : (
        <span>{label}</span>
      )}
      {action}
    </div>
  );
}

export default function Sidebar({
  buckets,
  tags,
  rules,
  channels,
  frameworks,
  selection,
  page,
  me,
  readOnly,
  onEditBucket,
  onEditRule,
  onEditFramework,
  onManageTags,
  onManageChannels,
}: Props) {
  const kind = selection?.kind;
  const isAdmin = me.role === "admin";
  return (
    <div className="bucket-nav">
      <NavLink href="#/logs" icon="description" active={kind === "all"}>
        All Logs
      </NavLink>
      <NavLink href="#/attack" icon="crisis_alert" active={kind === "mitre" || kind === "technique"}>
        MITRE ATT&CK
      </NavLink>
      <NavLink href="#/ot" icon="factory" active={kind === "ot" || kind === "otalert"}>
        ICS/OT Alerts
      </NavLink>
      <NavLink href="#/network" icon="lan" active={kind === "net"}>
        Network
      </NavLink>

      <SubHead
        label="Frameworks"
        href={hrefFor("frameworks")}
        active={page === "frameworks"}
        action={
          isAdmin && (
            <IconButton icon="add" label="New custom framework" variant="link" iconSize={16} onClick={() => onEditFramework(null)} />
          )
        }
      />
      {frameworks.map((f) => {
        const active =
          (selection?.kind === "framework" || selection?.kind === "frameworkitem") && selection.fw === f.id;
        const custom = f.id.startsWith("custom-");
        return (
          <div key={f.id} className="nav-row">
            <NavLink href={hrefFor({ kind: "framework", fw: f.id })} icon={custom ? "category" : "shield"} active={active} title={f.desc}>
              {f.short}
            </NavLink>
            {custom && isAdmin && (
              <IconButton
                className="nav-edit"
                icon="edit"
                label={`Edit framework ${f.short}`}
                variant="quiet"
                iconSize={15}
                onClick={() => onEditFramework(f)}
              />
            )}
          </div>
        );
      })}

      <SubHead
        label="Buckets"
        href={hrefFor("buckets")}
        active={page === "buckets"}
        action={!readOnly && <IconButton icon="add" label="New bucket" variant="link" iconSize={16} onClick={() => onEditBucket(null)} />}
      />
      {buckets.map((b) => {
        const active = selection?.kind === "bucket" && selection.id === b.id;
        const foreign = b.owner_id !== undefined && b.owner_id !== me.id;
        return (
          <div key={b.id} className="nav-row">
            <NavLink
              href={hrefFor({ kind: "bucket", id: b.id })}
              icon="folder"
              active={active}
              title={foreign && b.owner_name ? `Shared by ${b.owner_name}` : b.description || undefined}
            >
              {b.name}
              {b.shared && b.owner_id === me.id && (
                <span className="share-mark" title="Shared with others">
                  <Icon name="share" size={12} title="shared" />
                </span>
              )}
              {foreign && b.owner_name && <span className="owner-mark">· {b.owner_name}</span>}
            </NavLink>
            {b.can_edit && (
              <IconButton
                className="nav-edit"
                icon="edit"
                label={`Edit bucket ${b.name}`}
                variant="quiet"
                iconSize={15}
                onClick={() => onEditBucket(b)}
              />
            )}
          </div>
        );
      })}
      {buckets.length === 0 && <p className="nav-empty">Saved searches appear here.</p>}

      <SubHead
        label="Tags"
        action={!readOnly && <IconButton icon="sell" label="Manage tags" variant="link" iconSize={16} onClick={onManageTags} />}
      />
      <div className="nav-tags">
        {tags.map((t) => {
          const active = selection?.kind === "tag" && selection.id === t.id;
          return (
            <a
              key={t.id}
              href={hrefFor({ kind: "tag", id: t.id })}
              className={`nav-tag${active ? " active" : ""}`}
              aria-current={active ? "page" : undefined}
              aria-label={`Tag ${t.name}`}
            >
              <TagChip tag={t} />
            </a>
          );
        })}
        {tags.length === 0 && <p className="nav-empty">No tags yet.</p>}
      </div>

      <SubHead
        label="Rules"
        href={hrefFor("rules")}
        active={page === "rules"}
        action={!readOnly && <IconButton icon="add" label="New rule" variant="link" iconSize={16} onClick={() => onEditRule(null)} />}
      />
      {rules.map((r) => (
        <button
          key={r.id}
          type="button"
          className={`nav-link nav-button${r.enabled ? "" : " disabled"}`}
          title={`${readOnly ? "View" : "Edit"} rule ${r.name}${r.enabled ? "" : " (disabled)"}`}
          onClick={() => onEditRule(r)}
        >
          <Icon name="rule" size={16} />
          <span className="nav-text">
            {r.name}
            {!r.enabled && <span className="sr-only"> (disabled)</span>}
          </span>
        </button>
      ))}

      {!readOnly && (
        <>
          <SubHead
            label="Notifications"
            action={<IconButton icon="add" label="Manage notification channels" variant="link" iconSize={16} onClick={onManageChannels} />}
          />
          {channels.map((c) => (
            <button
              key={c.id}
              type="button"
              className={`nav-link nav-button${c.enabled ? "" : " disabled"}`}
              title={`Edit channel ${c.name}`}
              onClick={onManageChannels}
            >
              <Icon name="notifications" size={16} />
              <span className="nav-text">{c.name}</span>
            </button>
          ))}
          {channels.length === 0 && <p className="nav-empty">Webhook / Slack / email destinations.</p>}
        </>
      )}

      {/* Admin-only pages. */}
      {isAdmin && (
        <>
          <SubHead label="Admin" />
          <NavLink href={hrefFor("audit")} icon="history" active={page === "audit"}>
            Audit log
          </NavLink>
        </>
      )}
    </div>
  );
}

export function SidebarRail({
  tags,
  selection,
  page,
  me,
  readOnly,
  onManageTags,
  onManageChannels,
}: {
  tags: Tag[];
  selection: Selection | null;
  page: Page | null;
  me: User;
  readOnly: boolean;
  onManageTags: () => void;
  onManageChannels: () => void;
}) {
  const tagItems: MenuItem[] = tags.map((t) => ({
    id: `tag-${t.id}`,
    label: <TagChip tag={t} />,
    title: `Logs tagged ${t.name}`,
    onSelect: () => {
      location.hash = hrefFor({ kind: "tag", id: t.id });
    },
  }));
  if (!readOnly) tagItems.push({ id: "manage", label: "Manage tags…", icon: "tune", onSelect: onManageTags });
  return (
    <ul className="nav-list">
      {tagItems.length > 0 && (
        <li>
          <Menu
            label="Tags"
            placement="right"
            items={tagItems}
            triggerClassName={`nav-link nav-button${selection?.kind === "tag" ? " active" : ""}`}
            trigger={
              <>
                <Icon name="sell" size={17} />
                <span className="nav-text">Tags</span>
              </>
            }
          />
        </li>
      )}
      {!readOnly && (
        <li>
          <button type="button" className="nav-link nav-button" title="Notification channels" onClick={onManageChannels}>
            <Icon name="notifications" size={17} />
            <span className="nav-text">Notification channels</span>
          </button>
        </li>
      )}
      {me.role === "admin" && (
        <li>
          <NavLink href={hrefFor("audit")} icon="history" active={page === "audit"} title="Audit log">
            Audit log
          </NavLink>
        </li>
      )}
    </ul>
  );
}
