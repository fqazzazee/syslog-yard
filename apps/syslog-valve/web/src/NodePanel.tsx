import { useEffect, useState } from "react";
import { api, SEVERITIES, type CertStatus, type GraphNode, type MitreCatalog } from "./api";
import { Icon } from "./Icon";

const TITLES: Record<GraphNode["type"], string> = {
  source: "IN port",
  filter: "Filter",
  forward: "OUT port",
  cache: "Cache to disk",
  notify: "Notify",
};

export function NodePanel({
  node,
  shares,
  onChange,
  onDelete,
}: {
  node: GraphNode;
  shares: string[];
  onChange: (g: GraphNode) => void;
  onDelete?: () => void;
}) {
  const set = (patch: Partial<GraphNode["config"]>) =>
    onChange({ ...node, config: { ...node.config, ...patch } });

  return (
    <div className="panel">
      <h3>{TITLES[node.type]}</h3>
      <label>
        Name
        <input
          value={node.name}
          onChange={(e) => onChange({ ...node, name: e.target.value })}
        />
      </label>
      <label className="check">
        <input
          type="checkbox"
          checked={!node.disabled}
          onChange={(e) => onChange({ ...node, disabled: e.target.checked ? undefined : true })}
        />
        enabled — off keeps the block but leaves it out on Apply
      </label>

      {(node.type === "source" || node.type === "forward") && (
        <>
          <label>
            Transport
            <select
              value={node.config.transport}
              onChange={(e) => set({ transport: e.target.value as NonNullable<GraphNode["config"]["transport"]> })}
            >
              <option value="udp">udp</option>
              <option value="tcp">tcp</option>
              {node.type === "source" && <option value="udp+tcp">udp + tcp (both)</option>}
              <option value="tls">tls (RFC 5425)</option>
            </select>
          </label>
          {node.type === "source" ? (
            <label>
              Bind address
              <input
                value={node.config.bind ?? ""}
                placeholder="0.0.0.0"
                onChange={(e) => set({ bind: e.target.value })}
              />
            </label>
          ) : (
            <label>
              Destination host
              <input
                value={node.config.host ?? ""}
                placeholder="host or IP"
                onChange={(e) => set({ host: e.target.value })}
              />
            </label>
          )}
          <label>
            Port
            <input
              type="number"
              min={1}
              max={65535}
              value={node.config.port ?? 514}
              onChange={(e) => set({ port: Number(e.target.value) })}
            />
          </label>
          {node.config.transport === "tls" && node.type === "source" && <CertPanel />}
          {node.config.transport === "tls" && node.type === "forward" && (
            <label className="check">
              <input
                type="checkbox"
                checked={node.config.tlsVerify ?? false}
                onChange={(e) => set({ tlsVerify: e.target.checked })}
              />
              verify server certificate (system CAs)
            </label>
          )}
        </>
      )}

      {node.type === "filter" && (
        <>
          <label>
            Severity at least
            <select
              value={node.config.severityMax ?? -1}
              onChange={(e) => {
                const v = Number(e.target.value);
                set({ severityMax: v < 0 ? undefined : v });
              }}
            >
              <option value={-1}>— any severity —</option>
              {SEVERITIES.map((s, i) => (
                <option key={s} value={i}>
                  {s} or worse (≤ {i})
                </option>
              ))}
            </select>
          </label>
          <label>
            Program equals
            <input
              value={node.config.program ?? ""}
              placeholder="e.g. sshd (optional)"
              onChange={(e) => set({ program: e.target.value })}
            />
          </label>
          <label>
            Message matches (regex)
            <input
              value={node.config.match ?? ""}
              placeholder={'e.g. subtype="ips" (optional)'}
              onChange={(e) => set({ match: e.target.value })}
            />
          </label>
          <TechniqueSelect
            value={node.config.technique ?? ""}
            onChange={(technique) => set({ technique: technique || undefined })}
          />
          <p className="muted">
            Conditions are ANDed. Matching messages leave via <b>match</b>, the
            rest via <b>else</b>.
          </p>
        </>
      )}

      {node.type === "notify" && (
        <>
          <label>
            Destination
            <select
              value={node.config.notifyKind ?? "slack"}
              onChange={(e) => set({ notifyKind: e.target.value as "webhook" | "slack" })}
            >
              <option value="slack">Slack / Teams ({"{text}"})</option>
              <option value="webhook">Webhook (JSON)</option>
            </select>
          </label>
          <label>
            Webhook URL
            <input
              value={node.config.url ?? ""}
              placeholder="https://hooks.example.com/…"
              onChange={(e) => set({ url: e.target.value })}
            />
          </label>
          <label>
            Max notifications/min (0 = unlimited)
            <input
              type="number"
              min={0}
              value={node.config.ratePerMin ?? 30}
              onChange={(e) => set({ ratePerMin: Number(e.target.value) })}
            />
          </label>
          <NotifyTest kind={node.config.notifyKind ?? "slack"} url={node.config.url ?? ""} />
          <p className="muted">
            Matched messages are delivered in real time, before storage. For email, use a
            syslog-bucket channel. Changes take effect on Apply.
          </p>
        </>
      )}

      {node.type === "cache" && (
        <>
          <label>
            Location
            <select
              value={node.config.location ?? ""}
              onChange={(e) => set({ location: e.target.value })}
            >
              <option value="">local (/data/cache)</option>
              {shares.map((s) => (
                <option key={s} value={s}>
                  share: {s} (/shares/{s})
                </option>
              ))}
            </select>
          </label>
          <label>
            Folder
            <input
              value={node.config.dir ?? ""}
              placeholder="subfolder name"
              onChange={(e) => set({ dir: e.target.value })}
            />
          </label>
          <label>
            Rotate when size reaches (MB, 0 = daily)
            <input
              type="number"
              min={0}
              value={node.config.maxSizeMB ?? 0}
              onChange={(e) => set({ maxSizeMB: Number(e.target.value) })}
            />
          </label>
          <label>
            Rotations kept
            <input
              type="number"
              min={1}
              value={node.config.rotate ?? 7}
              onChange={(e) => set({ rotate: Number(e.target.value) })}
            />
          </label>
          <label>
            Delete rotated logs older than (days, 0 = never)
            <input
              type="number"
              min={0}
              value={node.config.maxAgeDays ?? 0}
              onChange={(e) => set({ maxAgeDays: Number(e.target.value) })}
            />
          </label>
          <label className="check">
            <input
              type="checkbox"
              checked={node.config.compress ?? false}
              onChange={(e) => set({ compress: e.target.checked })}
            />
            compress rotated logs
          </label>
        </>
      )}

      <p className="muted">Changes take effect on Apply.</p>
      {onDelete && (
        <button className="danger" onClick={onDelete} title="Remove this node and its wires (takes effect on Apply)">
          <Icon name="delete" size={15} /> Delete node
        </button>
      )}
    </div>
  );
}

// TechniqueSelect lets a filter match a MITRE ATT&CK technique, which the
// backend compiles to the matching syslog-ng pattern. Options are
// grouped by tactic.
function TechniqueSelect({ value, onChange }: { value: string; onChange: (id: string) => void }) {
  const [catalog, setCatalog] = useState<MitreCatalog | null>(null);

  useEffect(() => {
    api.mitre().then(setCatalog).catch(() => {});
  }, []);

  return (
    <label>
      MITRE ATT&CK technique
      <select value={value} onChange={(e) => onChange(e.target.value)}>
        <option value="">— none —</option>
        {catalog?.tactics.map((tac) => {
          const techs = catalog.techniques.filter((t) => t.tactics.includes(tac.short));
          if (techs.length === 0) return null;
          return (
            <optgroup key={tac.id} label={tac.name}>
              {techs.map((t) => (
                <option key={t.id} value={t.id}>
                  {t.id} · {t.name}
                </option>
              ))}
            </optgroup>
          );
        })}
      </select>
    </label>
  );
}

// NotifyTest delivers a synthetic message to the channel so the user can
// confirm wiring before applying the graph.
function NotifyTest({ kind, url }: { kind: string; url: string }) {
  const [status, setStatus] = useState("");
  const [busy, setBusy] = useState(false);
  const test = () => {
    setBusy(true);
    setStatus("sending…");
    api
      .notifyTest(kind, url)
      .then(() => setStatus("✓ test delivered"))
      .catch((e) => setStatus("✗ " + String(e)))
      .finally(() => setBusy(false));
  };
  return (
    <div className="cond-row">
      <button type="button" disabled={busy || !url} onClick={test}>
        Send test
      </button>
      {status && <span className="muted">{status}</span>}
    </div>
  );
}

// CertPanel shows the valve's TLS identity (shared by every TLS IN port)
// and lets the user (re)generate a self-signed pair for lab use.
function CertPanel() {
  const [cert, setCert] = useState<CertStatus | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");

  useEffect(() => {
    api.certs().then(setCert).catch((e) => setErr(String(e)));
  }, []);

  const generate = () => {
    if (cert?.exists && !confirm("Replace the existing certificate? Peers pinned to the old one will stop trusting the valve.")) return;
    setBusy(true);
    setErr("");
    api
      .generateCert()
      .then(setCert)
      .catch((e) => setErr(String(e)))
      .finally(() => setBusy(false));
  };

  return (
    <div className="cert-panel">
      {cert?.exists ? (
        <p className="muted">
          Certificate: {cert.subject} — expires {cert.notAfter?.slice(0, 10)}
          {cert.sans && cert.sans.length > 0 && <> · SANs: {cert.sans.join(", ")}</>}
          {cert.error && <span className="err"> ({cert.error})</span>}
        </p>
      ) : (
        <p className="muted">
          No certificate yet — TLS IN ports need one (served from /data/certs).
        </p>
      )}
      <button onClick={generate} disabled={busy}>
        {cert?.exists ? "Regenerate self-signed cert" : "Generate self-signed cert"}
      </button>
      {err && <p className="err">{err}</p>}
    </div>
  );
}
