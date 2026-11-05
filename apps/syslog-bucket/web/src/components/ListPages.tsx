// List pages behind the Buckets, Rules and Frameworks sections (#/buckets,
// #/rules, #/frameworks): one table each, so those sections are deep-link
// targets of their own and usable on a phone, where the rich nav sits in a
// drawer.
import { Badge, Button, EmptyState, PageHeader } from "../../../../shared/web/src/ui";
import { hrefFor } from "./../routes";
import type { Bucket, Framework, Rule, Tag, User } from "./../types";
import { PRIORITY_NAMES } from "./../types";

export function BucketsPage({
  buckets,
  me,
  readOnly,
  onEdit,
}: {
  buckets: Bucket[];
  me: User;
  readOnly: boolean;
  onEdit: (b: Bucket | null) => void;
}) {
  return (
    <>
      <PageHeader
        title="Buckets"
        icon="folder"
        meta="Saved searches, private or shared"
        actions={!readOnly && <Button variant="primary" icon="add" onClick={() => onEdit(null)}>New bucket</Button>}
      />
      <div className="page">
        {buckets.length === 0 ? (
          <EmptyState icon="folder" title="No buckets yet">
            A bucket is a saved search: a condition over host, app, severity, tags or ATT&CK techniques.
          </EmptyState>
        ) : (
          <div className="table-scroll">
            <table className="data-table">
              <thead>
                <tr>
                  <th scope="col">Bucket</th>
                  <th scope="col">Description</th>
                  <th scope="col">Owner</th>
                  <th scope="col">
                    <span className="sr-only">Actions</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {buckets.map((b) => {
                  const mine = b.owner_id === undefined || b.owner_id === me.id;
                  return (
                    <tr key={b.id}>
                      <td>
                        <a href={hrefFor({ kind: "bucket", id: b.id })}>{b.name}</a>{" "}
                        {b.shared && mine && <Badge>shared</Badge>}
                      </td>
                      <td className="muted">{b.description || "—"}</td>
                      <td>{mine ? "you" : (b.owner_name ?? "yard")}</td>
                      <td className="row-actions">
                        {b.can_edit && (
                          <Button size="sm" icon="edit" onClick={() => onEdit(b)} aria-label={`Edit bucket ${b.name}`}>
                            Edit
                          </Button>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </>
  );
}

function describeActions(r: Rule, tagsById: Map<number, Tag>): string {
  return r.actions
    .map((a) => {
      switch (a.type) {
        case "tag":
          return `tag ${tagsById.get(a.tag_id ?? 0)?.name ?? "?"}`;
        case "set_priority":
          return `priority ${PRIORITY_NAMES[a.priority ?? 0] ?? a.priority}`;
        case "suppress":
          return "suppress";
        case "notify":
          return "notify";
        case "set_mitre":
          return `ATT&CK ${(a.mitre ?? []).join(", ")}`;
        case "set_ot":
          return `OT ${(a.ot ?? []).join(", ")}`;
        default:
          return a.type;
      }
    })
    .join(" · ");
}

export function RulesPage({
  rules,
  tagsById,
  readOnly,
  onEdit,
}: {
  rules: Rule[];
  tagsById: Map<number, Tag>;
  readOnly: boolean;
  onEdit: (r: Rule | null) => void;
}) {
  return (
    <>
      <PageHeader
        title="Rules"
        icon="rule"
        meta="Run on every incoming entry, in order"
        actions={!readOnly && <Button variant="primary" icon="add" onClick={() => onEdit(null)}>New rule</Button>}
      />
      <div className="page">
        {rules.length === 0 ? (
          <EmptyState icon="rule" title="No rules yet">
            Rules tag, prioritize, suppress, classify or notify on matching entries as they arrive.
          </EmptyState>
        ) : (
          <div className="table-scroll">
            <table className="data-table">
              <thead>
                <tr>
                  <th scope="col">Rule</th>
                  <th scope="col">Actions</th>
                  <th scope="col">State</th>
                  <th scope="col">
                    <span className="sr-only">Edit</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {rules.map((r) => (
                  <tr key={r.id}>
                    <td>{r.name}</td>
                    <td className="muted">{describeActions(r, tagsById)}</td>
                    <td>{r.enabled ? <Badge tone="success">enabled</Badge> : <Badge>disabled</Badge>}</td>
                    <td className="row-actions">
                      {!readOnly && (
                        <Button size="sm" icon="edit" onClick={() => onEdit(r)} aria-label={`Edit rule ${r.name}`}>
                          Edit
                        </Button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </>
  );
}

export function FrameworksPage({
  frameworks,
  isAdmin,
  onEdit,
}: {
  frameworks: Framework[];
  isAdmin: boolean;
  onEdit: (f: Framework | null) => void;
}) {
  return (
    <>
      <PageHeader
        title="Frameworks"
        icon="shield"
        meta="Coverage matrices over classified entries"
        actions={
          isAdmin && (
            <Button variant="primary" icon="add" onClick={() => onEdit(null)}>
              New custom framework
            </Button>
          )
        }
      />
      <div className="page">
        <ul className="fw-cards">
          <li>
            <a className="fw-card" href="#/attack">
              <b>MITRE ATT&CK</b>
              <span className="muted">Enterprise techniques by tactic</span>
            </a>
          </li>
          <li>
            <a className="fw-card" href="#/ot">
              <b>ICS/OT alerts</b>
              <span className="muted">Claroty-style OT alert types</span>
            </a>
          </li>
          {frameworks.map((f) => {
            const custom = f.id.startsWith("custom-");
            return (
              <li key={f.id}>
                <a className="fw-card" href={hrefFor({ kind: "framework", fw: f.id })}>
                  <b>
                    {f.name} {custom && <Badge>custom</Badge>}
                  </b>
                  <span className="muted">{f.desc}</span>
                </a>
                {custom && isAdmin && (
                  <Button size="sm" variant="link" icon="edit" onClick={() => onEdit(f)} aria-label={`Edit framework ${f.short}`}>
                    Edit
                  </Button>
                )}
              </li>
            );
          })}
        </ul>
      </div>
    </>
  );
}
