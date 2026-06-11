import { patchEntry, tagEntry, untagEntry } from "./../api";
import type { Entry, Tag } from "./../types";
import { PRIORITY_NAMES, SEVERITY_NAMES, STATUS_NAMES } from "./../types";
import { Icon } from "./Icon";
import { TagChip, TagPicker } from "./Tags";

interface Props {
  entry: Entry;
  tags: Tag[];
  tagsById: Map<number, Tag>;
  readOnly: boolean; // viewer role: triage controls hidden
  onClose: () => void;
  onUpdated: (e: Entry) => void;
}

export default function EntryDetail({ entry, tags, tagsById, readOnly, onClose, onUpdated }: Props) {
  const structured = entry.structured ?? {};
  const structuredKeys = Object.keys(structured);

  const update = (op: Promise<Entry>) => {
    op.then(onUpdated).catch(() => {});
  };

  return (
    <aside className="detail">
      <div className="detail-head">
        <h2>
          Entry #{entry.id}
          {entry.suppressed && <span className="badge muted">suppressed</span>}
        </h2>
        <button onClick={onClose}>
          <Icon name="close" size={18} />
        </button>
      </div>

      <div className="triage">
        <label>
          Status
          <select
            value={entry.status}
            disabled={readOnly}
            onChange={(e) => update(patchEntry(entry.id, { status: e.target.value }))}
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
            disabled={readOnly}
            onChange={(e) => update(patchEntry(entry.id, { priority: Number(e.target.value) }))}
          >
            {PRIORITY_NAMES.map((p, n) => (
              <option key={n} value={n}>
                {p}
              </option>
            ))}
          </select>
        </label>
      </div>

      <div className="detail-tags">
        {(entry.tag_ids ?? []).map((id) => {
          const tag = tagsById.get(id);
          return tag ? (
            <TagChip key={id} tag={tag} onRemove={readOnly ? undefined : () => update(untagEntry(entry.id, id))} />
          ) : null;
        })}
        {!readOnly && (
          <TagPicker tags={tags} exclude={entry.tag_ids ?? []} onPick={(id) => update(tagEntry(entry.id, id))} />
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

      {(entry.mitre ?? []).length > 0 && (
        <>
          <h3>ATT&CK techniques</h3>
          <div className="detail-mitre">
            {entry.mitre.map((id) => (
              <a
                key={id}
                className="mitre-chip"
                href={`https://attack.mitre.org/techniques/${id.replace(".", "/")}/`}
                target="_blank"
                rel="noreferrer"
                title="Open on attack.mitre.org"
              >
                {id}
              </a>
            ))}
          </div>
        </>
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
