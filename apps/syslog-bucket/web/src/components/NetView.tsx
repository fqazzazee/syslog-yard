import { useCallback, useEffect, useState } from "react";
import { fetchNetEntries, fetchNetSummary, putNetConfig, refreshNetFeeds } from "./../api";
import type { Entry, Filters, NetConfig, NetSummary, User } from "./../types";
import { Icon } from "./Icon";

interface Props {
  filters: Filters; // the range filter drives the scan window
  me: User | null;
}

// Direction tiles, in display order. "external" = observed transit
// (external→external), e.g. a perimeter device reporting blocked scans.
const DIRECTIONS = [
  { id: "inbound", label: "Inbound", hint: "external → internal" },
  { id: "outbound", label: "Outbound", hint: "internal → external" },
  { id: "internal", label: "Lateral", hint: "internal → internal" },
  { id: "external", label: "External", hint: "external → external" },
  { id: "unknown", label: "Unclassified", hint: "no parseable src/dst pair" },
];

const SCOPES = [
  { id: "internal", label: "RFC1918 / internal", hint: "10/8, 172.16/12, 192.168/16, ULA" },
  { id: "external", label: "External / public", hint: "publicly routable addresses" },
  { id: "special", label: "Special-use", hint: "loopback, link-local, CGNAT, multicast…" },
];

// NetView classifies recent traffic by the IP addresses entries mention:
// scopes (internal/external/special), flow direction, and the category sets
// kept fresh by the server (threat-intel feeds, O365 ranges, custom CIDR
// groups). Classification happens at read time, so a feed update flags
// matching history immediately.
export default function NetView({ filters, me }: Props) {
  const minutes = filters.range ? Number(filters.range) : 24 * 60;
  const [sum, setSum] = useState<NetSummary | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [drill, setDrill] = useState<{ label: string; q: { class?: string; ip?: string } } | null>(null);
  const [drillEntries, setDrillEntries] = useState<Entry[] | null>(null);
  const [busy, setBusy] = useState(false);
  const admin = me?.role === "admin";

  const reload = useCallback(() => {
    fetchNetSummary(minutes).then(setSum).catch((e) => setError(String(e)));
  }, [minutes]);

  useEffect(() => {
    setDrill(null);
    reload();
    const t = setInterval(reload, 30_000);
    return () => clearInterval(t);
  }, [reload]);

  useEffect(() => {
    if (!drill) {
      setDrillEntries(null);
      return;
    }
    let stale = false;
    setDrillEntries(null);
    fetchNetEntries({ ...drill.q, minutes })
      .then((es) => !stale && setDrillEntries(es))
      .catch((e) => !stale && setError(String(e)));
    return () => {
      stale = true;
    };
  }, [drill, minutes]);

  const refresh = async () => {
    setBusy(true);
    try {
      const r = await refreshNetFeeds();
      setSum((s) => (s ? { ...s, feeds: r.feeds } : s));
      reload();
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  };

  if (error) return <div className="error">{error}</div>;
  if (!sum) return <div className="mitre-view empty">Classifying recent traffic…</div>;

  const malTotal = sum.malicious.reduce((a, h) => a + h.count, 0);

  return (
    <div className="mitre-view net-view">
      <div className="mitre-head">
        <p className="mitre-intro">
          {sum.scanned.toLocaleString()} entries classified by the addresses they mention
          {sum.truncated ? " (window capped — narrow the time filter for full coverage)" : ""}.
          Threat feeds match at read time, so refreshed databases re-flag history.
        </p>
        {malTotal > 0 && (
          <div className="net-mal-banner">
            <Icon name="crisis_alert" size={15} /> {malTotal.toLocaleString()} entries mention{" "}
            {sum.malicious.length} known-malicious address{sum.malicious.length === 1 ? "" : "es"}
            <button onClick={() => setDrill({ label: "malicious traffic", q: { class: "malicious" } })}>
              view entries
            </button>
          </div>
        )}
      </div>

      <h3 className="net-h">Direction</h3>
      <div className="net-cards">
        {DIRECTIONS.map((d) => (
          <button
            key={d.id}
            className={`net-card${(sum.directions[d.id] ?? 0) > 0 ? " hit" : ""}`}
            title={d.hint}
            onClick={() => setDrill({ label: `${d.label.toLowerCase()} traffic`, q: { class: `dir:${d.id}` } })}
          >
            <span className="net-card-n">{(sum.directions[d.id] ?? 0).toLocaleString()}</span>
            {d.label}
          </button>
        ))}
      </div>

      <h3 className="net-h">Address scopes</h3>
      <div className="net-cards">
        {SCOPES.map((s) => (
          <button
            key={s.id}
            className={`net-card${(sum.scopes[s.id] ?? 0) > 0 ? " hit" : ""}`}
            title={s.hint}
            onClick={() => setDrill({ label: s.label, q: { class: `scope:${s.id}` } })}
          >
            <span className="net-card-n">{(sum.scopes[s.id] ?? 0).toLocaleString()}</span>
            {s.label}
          </button>
        ))}
      </div>

      <h3 className="net-h">Categories</h3>
      <div className="net-cards">
        {sum.categories.map((c) => (
          <button
            key={c.id}
            className={`net-card cat-${c.category}${c.count > 0 ? " hit" : ""}`}
            title={`category: ${c.category}`}
            onClick={() => setDrill({ label: c.label, q: { class: `set:${c.id}` } })}
          >
            <span className="net-card-n">{c.count.toLocaleString()}</span>
            {c.label}
          </button>
        ))}
        {sum.categories.length === 0 && <span className="muted">No category sets enabled.</span>}
      </div>

      {sum.malicious.length > 0 && (
        <>
          <h3 className="net-h net-h-bad">
            <Icon name="crisis_alert" size={14} /> Flagged addresses
          </h3>
          <table className="net-table">
            <thead>
              <tr>
                <th>address</th>
                <th>entries</th>
                <th>flagged by</th>
                <th>last seen</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {sum.malicious.map((h) => (
                <tr key={h.ip}>
                  <td>
                    <code className="net-bad-ip">{h.ip}</code>
                  </td>
                  <td>{h.count}</td>
                  <td>{h.feeds.map((f) => sum.feeds.find((x) => x.id === f)?.label ?? f).join(", ")}</td>
                  <td>{new Date(h.last_seen).toLocaleString()}</td>
                  <td>
                    <button onClick={() => setDrill({ label: h.ip, q: { ip: h.ip } })}>entries</button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      )}

      {drill && (
        <>
          <h3 className="net-h">
            Entries — {drill.label}
            <button className="net-close" onClick={() => setDrill(null)}>
              <Icon name="close" size={13} /> close
            </button>
          </h3>
          {!drillEntries ? (
            <div className="muted">Loading…</div>
          ) : drillEntries.length === 0 ? (
            <div className="muted">No matching entries in this window.</div>
          ) : (
            <table className="net-table net-entries">
              <thead>
                <tr>
                  <th>time</th>
                  <th>host</th>
                  <th>app</th>
                  <th>message</th>
                </tr>
              </thead>
              <tbody>
                {drillEntries.map((e) => (
                  <tr key={e.id}>
                    <td>{new Date(e.received_at).toLocaleString()}</td>
                    <td>{e.host}</td>
                    <td>{e.app_name}</td>
                    <td className="net-msg">{e.msg}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </>
      )}

      <h3 className="net-h">
        Online databases
        {admin && (
          <button className="net-close" disabled={busy} onClick={refresh} title="Fetch every enabled feed now">
            <Icon name="cached" size={13} /> {busy ? "refreshing…" : "refresh now"}
          </button>
        )}
      </h3>
      <table className="net-table">
        <thead>
          <tr>
            <th>feed</th>
            <th>category</th>
            <th>prefixes</th>
            <th>updated</th>
            <th>status</th>
          </tr>
        </thead>
        <tbody>
          {sum.feeds.map((f) => (
            <tr key={f.id} className={f.enabled ? "" : "net-off"}>
              <td>{f.label}</td>
              <td>{f.category}</td>
              <td>{f.prefixes.toLocaleString()}</td>
              <td>{f.fetched_at && !f.fetched_at.startsWith("0001") ? new Date(f.fetched_at).toLocaleString() : "never"}</td>
              <td>
                {!f.enabled ? (
                  <span className="muted">disabled</span>
                ) : f.error ? (
                  <span className="net-err" title={f.error}>
                    fetch failed
                  </span>
                ) : (
                  "ok"
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      {admin && <NetConfigEditor onSaved={reload} />}
    </div>
  );
}

// NetConfigEditor lets an admin toggle feeds and maintain custom CIDR
// categories ("VPN pool", "branch offices", …). Loaded lazily so the view
// itself stays read-only for analysts.
function NetConfigEditor({ onSaved }: { onSaved: () => void }) {
  const [open, setOpen] = useState(false);
  const [cfg, setCfg] = useState<NetConfig | null>(null);
  const [labels, setLabels] = useState<Record<string, string>>({});
  const [err, setErr] = useState("");
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    if (!open || cfg) return;
    import("./../api").then(({ fetchNetConfig }) =>
      fetchNetConfig()
        .then((r) => {
          setCfg(r.config);
          setLabels(Object.fromEntries(r.feeds.map((f) => [f.id, f.label])));
        })
        .catch((e) => setErr(String(e))),
    );
  }, [open, cfg]);

  const save = async () => {
    if (!cfg) return;
    setSaving(true);
    setErr("");
    try {
      await putNetConfig(cfg);
      onSaved();
    } catch (e) {
      setErr(String(e));
    } finally {
      setSaving(false);
    }
  };

  if (!open) {
    return (
      <button className="linkish net-cfg-toggle" onClick={() => setOpen(true)}>
        <Icon name="tune" size={14} /> Configure feeds &amp; custom categories…
      </button>
    );
  }
  if (!cfg) return <div className="muted">{err || "Loading config…"}</div>;

  return (
    <div className="net-cfg">
      <h4>Feeds</h4>
      {Object.keys(cfg.feeds).map((id) => (
        <label key={id} className="check">
          <input
            type="checkbox"
            checked={cfg.feeds[id]}
            onChange={(e) => setCfg({ ...cfg, feeds: { ...cfg.feeds, [id]: e.target.checked } })}
          />
          {labels[id] ?? id}
        </label>
      ))}
      <h4>Custom categories</h4>
      {cfg.custom.map((c, i) => (
        <div key={i} className="net-cfg-cat">
          <input
            placeholder="name (e.g. VPN pool)"
            value={c.name}
            onChange={(e) => {
              const custom = [...cfg.custom];
              custom[i] = { ...c, name: e.target.value };
              setCfg({ ...cfg, custom });
            }}
          />
          <input
            placeholder="CIDRs, comma-separated (10.8.0.0/16, 192.0.2.7)"
            value={c.cidrs.join(", ")}
            onChange={(e) => {
              const custom = [...cfg.custom];
              custom[i] = { ...c, cidrs: e.target.value.split(",").map((s) => s.trim()).filter(Boolean) };
              setCfg({ ...cfg, custom });
            }}
          />
          <button onClick={() => setCfg({ ...cfg, custom: cfg.custom.filter((_, j) => j !== i) })}>
            <Icon name="delete" size={13} />
          </button>
        </div>
      ))}
      <button onClick={() => setCfg({ ...cfg, custom: [...cfg.custom, { name: "", cidrs: [] }] })}>
        <Icon name="add" size={13} /> Add category
      </button>
      {err && <div className="error">{err}</div>}
      <div className="net-cfg-actions">
        <button className="primary" disabled={saving} onClick={save}>
          {saving ? "Saving…" : "Save"}
        </button>
        <button onClick={() => setOpen(false)}>Close</button>
      </div>
    </div>
  );
}
