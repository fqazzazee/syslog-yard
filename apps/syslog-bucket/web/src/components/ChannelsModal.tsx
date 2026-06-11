import { useEffect, useState } from "react";
import { createChannel, deleteChannel, fetchNotificationLog, testChannel, updateChannel } from "./../api";
import type { Channel, ChannelKind, Delivery } from "./../types";
import Modal from "./Modal";

interface Props {
  channels: Channel[];
  onClose: (changed: boolean) => void;
}

const KIND_LABEL: Record<ChannelKind, string> = {
  webhook: "Webhook (JSON)",
  slack: "Slack / Teams",
  smtp: "Email (SMTP)",
};

export default function ChannelsModal({ channels, onClose }: Props) {
  const [drafts, setDrafts] = useState<Channel[]>(channels);
  const [newName, setNewName] = useState("");
  const [newKind, setNewKind] = useState<ChannelKind>("slack");
  const [error, setError] = useState<string | null>(null);
  const [status, setStatus] = useState<Record<number, string>>({});
  const [changed, setChanged] = useState(false);

  const run = async (op: () => Promise<unknown>) => {
    setError(null);
    try {
      await op();
      setChanged(true);
      return true;
    } catch (e) {
      setError(String(e));
      return false;
    }
  };

  const patch = (i: number, p: Partial<Channel>) =>
    setDrafts((d) => d.map((c, j) => (j === i ? { ...c, ...p } : c)));
  const patchConfig = (i: number, k: string, v: unknown) =>
    setDrafts((d) => d.map((c, j) => (j === i ? { ...c, config: { ...c.config, [k]: v } } : c)));

  const add = async () => {
    const ok = await run(async () => {
      const c = await createChannel({ name: newName.trim(), kind: newKind, config: {}, enabled: true, rate_per_min: 30 });
      setDrafts((d) => [...d, c]);
    });
    if (ok) setNewName("");
  };

  const save = (i: number) =>
    run(async () => {
      const saved = await updateChannel(drafts[i]);
      setDrafts((d) => d.map((c, j) => (j === i ? saved : c)));
      setStatus((s) => ({ ...s, [drafts[i].id]: "saved" }));
    });

  const test = (c: Channel) =>
    run(async () => {
      setStatus((s) => ({ ...s, [c.id]: "sending…" }));
      try {
        await testChannel(c.id);
        setStatus((s) => ({ ...s, [c.id]: "✓ test delivered" }));
      } catch (e) {
        setStatus((s) => ({ ...s, [c.id]: "✗ " + String(e) }));
        throw e;
      }
    });

  const remove = (c: Channel) => {
    if (!confirm(`Delete channel "${c.name}"? Rules notifying it will stop firing.`)) return;
    void run(async () => {
      await deleteChannel(c.id);
      setDrafts((d) => d.filter((x) => x.id !== c.id));
    });
  };

  return (
    <Modal title="Notification channels" onClose={() => onClose(changed)}>
      <p className="hint">
        Channels are fired by a rule's <b>Notify</b> action. SMTP passwords are write-only — leave blank to keep the
        stored one.
      </p>

      {drafts.map((c, i) => (
        <div className="channel-card" key={c.id}>
          <div className="cond-row">
            <input
              className="cond-value"
              value={c.name}
              onChange={(e) => patch(i, { name: e.target.value })}
            />
            <span className="channel-kind">{KIND_LABEL[c.kind]}</span>
            <label className="check">
              <input type="checkbox" checked={c.enabled} onChange={(e) => patch(i, { enabled: e.target.checked })} />
              on
            </label>
            <button type="button" className="linkish" title="Delete channel" onClick={() => remove(c)}>
              ✕
            </button>
          </div>

          <ChannelConfig channel={c} onConfig={(k, v) => patchConfig(i, k, v)} />

          <div className="cond-row">
            <label className="rate">
              max/min
              <input
                type="number"
                min={0}
                value={c.rate_per_min}
                onChange={(e) => patch(i, { rate_per_min: Number(e.target.value) })}
              />
            </label>
            <button type="button" className="primary" onClick={() => void save(i)}>
              Save
            </button>
            <button type="button" onClick={() => void test(c)}>
              Send test
            </button>
            {status[c.id] && <span className="channel-status">{status[c.id]}</span>}
          </div>
        </div>
      ))}

      <div className="cond-row channel-new">
        <select value={newKind} onChange={(e) => setNewKind(e.target.value as ChannelKind)}>
          {(Object.keys(KIND_LABEL) as ChannelKind[]).map((k) => (
            <option key={k} value={k}>
              {KIND_LABEL[k]}
            </option>
          ))}
        </select>
        <input
          className="cond-value"
          placeholder="new channel name"
          value={newName}
          onChange={(e) => setNewName(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && newName.trim() && void add()}
        />
        <button type="button" className="primary" disabled={!newName.trim()} onClick={() => void add()}>
          Add
        </button>
      </div>

      {error && <div className="error">{error}</div>}
      <RecentDeliveries />
    </Modal>
  );
}

// ChannelConfig renders the kind-specific fields.
function ChannelConfig({ channel, onConfig }: { channel: Channel; onConfig: (k: string, v: unknown) => void }) {
  const cfg = channel.config as Record<string, unknown>;
  const str = (k: string) => (cfg[k] === undefined || cfg[k] === null ? "" : String(cfg[k]));

  if (channel.kind === "smtp") {
    const to = Array.isArray(cfg.to) ? (cfg.to as string[]).join(", ") : str("to");
    return (
      <div className="channel-config">
        <label>
          SMTP host
          <input value={str("host")} placeholder="smtp.example.com" onChange={(e) => onConfig("host", e.target.value)} />
        </label>
        <label>
          Port
          <input
            type="number"
            value={str("port") || 587}
            onChange={(e) => onConfig("port", Number(e.target.value))}
          />
        </label>
        <label>
          From
          <input value={str("from")} placeholder="alerts@example.com" onChange={(e) => onConfig("from", e.target.value)} />
        </label>
        <label>
          To (comma-separated)
          <input
            value={to}
            placeholder="soc@example.com"
            onChange={(e) => onConfig("to", e.target.value.split(",").map((s) => s.trim()).filter(Boolean))}
          />
        </label>
        <label>
          Username
          <input value={str("username")} onChange={(e) => onConfig("username", e.target.value)} />
        </label>
        <label>
          Password {cfg.has_password ? "(stored)" : ""}
          <input
            type="password"
            placeholder={cfg.has_password ? "leave blank to keep" : ""}
            value={str("password")}
            onChange={(e) => onConfig("password", e.target.value)}
          />
        </label>
        <label>
          TLS
          <select value={str("tls") || "starttls"} onChange={(e) => onConfig("tls", e.target.value)}>
            <option value="starttls">STARTTLS (587)</option>
            <option value="tls">Implicit TLS (465)</option>
            <option value="none">None (lab only)</option>
          </select>
        </label>
      </div>
    );
  }
  // webhook / slack
  return (
    <div className="channel-config">
      <label>
        {channel.kind === "slack" ? "Incoming webhook URL" : "Endpoint URL"}
        <input
          value={str("url")}
          placeholder="https://hooks.example.com/…"
          onChange={(e) => onConfig("url", e.target.value)}
        />
      </label>
    </div>
  );
}

// RecentDeliveries shows the latest delivery attempts across all channels.
function RecentDeliveries() {
  const [log, setLog] = useState<Delivery[]>([]);
  useEffect(() => {
    fetchNotificationLog().then(setLog).catch(() => {});
  }, []);
  if (log.length === 0) return null;
  return (
    <div className="delivery-log">
      <h4>Recent deliveries</h4>
      {log.slice(0, 15).map((d) => (
        <div key={d.id} className={`delivery delivery-${d.status}`}>
          <span className="delivery-status">{d.status}</span>
          <span className="delivery-time">{new Date(d.sent_at).toLocaleTimeString()}</span>
          <span className="delivery-detail">{d.detail || "—"}</span>
        </div>
      ))}
    </div>
  );
}
