import { useRef, useState } from "react";
import { Badge, Banner, IconButton } from "../../../../shared/web/src/ui";
import {
  addEntryMitre,
  addEntryOT,
  delEntryMitre,
  delEntryOT,
  patchEntry,
  tagEntry,
  untagEntry,
} from "./../api";
import type { Entry, MitreCatalog, OTCatalog, Tag } from "./../types";
import { PRIORITY_NAMES, SEVERITY_NAMES, STATUS_NAMES } from "./../types";
import { Icon } from "./Icon";
import { TagChip, TagPicker } from "./Tags";

interface Props {
  entry: Entry;
  tags: Tag[];
  tagsById: Map<number, Tag>;
  mitreCatalog: MitreCatalog | null;
  otCatalog: OTCatalog | null;
  readOnly: boolean; // viewer role: triage controls hidden
  onClose: () => void;
  onUpdated: (e: Entry) => void;
  onCreateRule: (e: Entry) => void;
}

// CodePicker is a small "+ add" dropdown of catalog codes not already present.
function CodePicker({
  options,
  exclude,
  label,
  disabled,
  onPick,
}: {
  options: { id: string; name: string }[];
  exclude: string[];
  label: string;
  disabled?: boolean;
  onPick: (id: string) => void;
}) {
  const left = options.filter((o) => !exclude.includes(o.id));
  if (left.length === 0) return null;
  return (
    <select
      className="code-picker"
      value=""
      disabled={disabled}
      onChange={(e) => e.target.value && onPick(e.target.value)}
      aria-label={label}
    >
      <option value="">{label}</option>
      {left.map((o) => (
        <option key={o.id} value={o.id}>
          {o.id} — {o.name}
        </option>
      ))}
    </select>
  );
}

export default function EntryDetail({
  entry,
  tags,
  tagsById,
  mitreCatalog,
  otCatalog,
  readOnly,
  onClose,
  onUpdated,
  onCreateRule,
}: Props) {
  const structured = entry.structured ?? {};
  const structuredKeys = Object.keys(structured);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  // One change at a time: overlapping PATCHes could resolve out of order and
  // leave the pane showing a stale state. The ref guards against a second
  // event slipping in before the disabled controls re-render.
  const busyRef = useRef(false);

  const update = (op: () => Promise<Entry>) => {
    if (busyRef.current) return;
    busyRef.current = true;
    setBusy(true);
    setError(null);
    op()
      .then(onUpdated)
      .catch((e) => setError(e instanceof Error ? e.message : String(e)))
      .finally(() => {
        busyRef.current = false;
        setBusy(false);
      });
  };
  const locked = readOnly || busy;

  const mitre = entry.mitre ?? [];
  const ot = entry.ot ?? [];

  return (
    <aside className="detail" aria-labelledby="entry-detail-title">
      <div className="detail-head">
        <h2 id="entry-detail-title">
          Entry #{entry.id}
          {entry.suppressed && <Badge>suppressed</Badge>}
        </h2>
        <IconButton icon="close" label="Close entry details" onClick={onClose} />
      </div>

      <div className="triage">
        <label>
          Status
          <select
            value={entry.status}
            disabled={locked}
            onChange={(e) => update(() => patchEntry(entry.id, { status: e.target.value }))}
          >
            {STATUS_NAMES.map((s) => (
              <option key={s} value={s}>
                {s}
              </option>
            ))}
          </select>
        </label>
        <label>
          Priority
          <select
            value={entry.priority}
            disabled={locked}
            onChange={(e) => update(() => patchEntry(entry.id, { priority: Number(e.target.value) }))}
          >
            {PRIORITY_NAMES.map((p, n) => (
              <option key={n} value={n}>
                {p}
              </option>
            ))}
          </select>
        </label>
      </div>
      {error && <Banner kind="error">{error}</Banner>}

      <div className="detail-tags">
        {(entry.tag_ids ?? []).map((id) => {
          const tag = tagsById.get(id);
          return tag ? (
            <TagChip
              key={id}
              tag={tag}
              disabled={busy}
              onRemove={readOnly ? undefined : () => update(() => untagEntry(entry.id, id))}
            />
          ) : null;
        })}
        {!readOnly && (
          <TagPicker tags={tags} exclude={entry.tag_ids ?? []} disabled={busy} onPick={(id) => update(() => tagEntry(entry.id, id))} />
        )}
      </div>

      <dl>
        <dt>Received</dt>
        <dd>{new Date(entry.received_at).toLocaleString()}</dd>
        {entry.device_time && (
          <>
            <dt>Device time</dt>
            <dd>{new Date(entry.device_time).toLocaleString()}</dd>
          </>
        )}
        <dt>Host</dt>
        <dd>
          {entry.host}
          {entry.source_ip ? ` (${entry.source_ip})` : ""}
        </dd>
        <dt>App</dt>
        <dd>{entry.app_name || "—"}</dd>
        {entry.device_class && (
          <>
            <dt>Device class</dt>
            <dd>{entry.device_class}</dd>
          </>
        )}
        <dt>Severity</dt>
        <dd>
          <span className={`badge sev-${entry.severity}`}>
            {SEVERITY_NAMES[entry.severity] ?? entry.severity}
          </span>
        </dd>
        {entry.facility !== undefined && entry.facility !== null && (
          <>
            <dt>Facility</dt>
            <dd>{entry.facility}</dd>
          </>
        )}
      </dl>

      {(mitre.length > 0 || !readOnly) && (
        <>
          <h3>ATT&CK techniques</h3>
          <div className="detail-mitre">
            {mitre.map((id) => (
              <span key={id} className="mitre-chip editable">
                <a
                  href={`https://attack.mitre.org/techniques/${id.split(".").map(encodeURIComponent).join("/")}/`}
                  target="_blank"
                  rel="noreferrer"
                  title="Open on attack.mitre.org"
                >
                  {id}
                </a>
                {!readOnly && (
                  <button
                    className="chip-x"
                    title="Remove classification"
                    aria-label={`Remove technique ${id}`}
                    disabled={busy}
                    onClick={() => update(() => delEntryMitre(entry.id, id))}
                  >
                    <Icon name="close" size={12} />
                  </button>
                )}
              </span>
            ))}
            {!readOnly && mitreCatalog && (
              <CodePicker
                options={mitreCatalog.techniques}
                exclude={mitre}
                label="+ technique"
                disabled={busy}
                onPick={(id) => update(() => addEntryMitre(entry.id, id))}
              />
            )}
          </div>
        </>
      )}

      {(ot.length > 0 || !readOnly) && (
        <>
          <h3>OT alerts</h3>
          <div className="detail-mitre">
            {ot.map((id) => (
              <span key={id} className="mitre-chip ot-chip editable" title="Claroty OT alert type">
                {id}
                {!readOnly && (
                  <button
                    className="chip-x"
                    title="Remove classification"
                    aria-label={`Remove OT code ${id}`}
                    disabled={busy}
                    onClick={() => update(() => delEntryOT(entry.id, id))}
                  >
                    <Icon name="close" size={12} />
                  </button>
                )}
              </span>
            ))}
            {!readOnly && otCatalog && (
              <CodePicker
                options={otCatalog.alert_types}
                exclude={ot}
                label="+ OT code"
                disabled={busy}
                onPick={(id) => update(() => addEntryOT(entry.id, id))}
              />
            )}
          </div>
        </>
      )}

      {!readOnly && (
        <button className="linkish promote" title="Make this classification reusable" onClick={() => onCreateRule(entry)}>
          <Icon name="rule" size={14} /> Create rule from this entry
        </button>
      )}

      <h3>Message</h3>
      <pre className="raw">{entry.msg}</pre>

      {structuredKeys.length > 0 && (
        <>
          <h3>Parsed fields</h3>
          <dl className="structured">
            {structuredKeys.map((k) => (
              <div key={k}>
                <dt>{k}</dt>
                <dd>{String(structured[k])}</dd>
              </div>
            ))}
          </dl>
        </>
      )}
    </aside>
  );
}
