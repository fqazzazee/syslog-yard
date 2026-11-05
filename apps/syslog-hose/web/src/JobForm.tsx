import { useEffect, useState } from "react";
import { Dialog } from "../../../shared/web/src/Dialog";
import { errorText } from "../../../shared/web/src/http";
import { Banner, Button } from "../../../shared/web/src/ui";
import { api, type Job, type PresetSummary } from "./api";

const DEFAULTS: Partial<Job> = {
  name: "",
  preset: "",
  host: "",
  port: 514,
  transport: "udp",
  tlsInsecure: false,
  format: "",
  rate: 5,
  rateMode: "steady",
  jitterPct: 30,
  burstFactor: 5,
  burstEvery: 30,
  burstLen: 5,
  durationSec: 0,
  maxEvents: 0,
  hostname: "",
  appname: "",
  facility: -1,
  autostart: false,
};

export function JobForm(props: {
  initial: Partial<Job>;
  presets: PresetSummary[];
  onClose: () => void;
  onSaved: () => void;
}) {
  const editingId = props.initial.id;
  const [cfg, setCfg] = useState<Partial<Job>>({ ...DEFAULTS, ...props.initial });
  const [samples, setSamples] = useState<string[]>([]);
  const [error, setError] = useState("");

  useEffect(() => {
    if (!cfg.preset && props.presets.length > 0) {
      setCfg((c) => ({ ...c, preset: props.presets[0].name }));
    }
  }, [props.presets]);

  const set = <K extends keyof Job>(key: K, val: Job[K]) =>
    setCfg((c) => ({ ...c, [key]: val }));

  const preview = () => {
    setError("");
    api
      .preview({ preset: cfg.preset, count: 5, hostname: cfg.hostname, format: cfg.format })
      .then((r) => setSamples(r.samples))
      .catch((e: unknown) => setError(errorText(e)));
  };

  const save = () => {
    setError("");
    const p = editingId ? api.updateJob(editingId, cfg) : api.createJob(cfg);
    p.then(props.onSaved).catch((e: unknown) => setError(errorText(e)));
  };

  return (
    <Dialog
      title={editingId ? "Edit job" : "New job"}
      size="lg"
      onClose={props.onClose}
      footer={
        <>
          <Button onClick={preview} className="danger-left">
            Preview samples
          </Button>
          <Button onClick={props.onClose}>Cancel</Button>
          <Button variant="primary" onClick={save}>
            {editingId ? "Save" : "Create"}
          </Button>
        </>
      }
    >
        <div className="form-grid">
          <label>
            Name
            <input
              value={cfg.name ?? ""}
              placeholder="Edge FortiGate"
              autoFocus
              onChange={(e) => set("name", e.target.value)}
            />
          </label>
          <label>
            Preset
            <select value={cfg.preset} onChange={(e) => set("preset", e.target.value)}>
              {props.presets.map((p) => (
                <option key={p.name} value={p.name}>
                  {p.vendor} — {p.name}
                </option>
              ))}
            </select>
          </label>
          <label>
            Destination host
            <input
              value={cfg.host ?? ""}
              placeholder="10.0.0.50"
              onChange={(e) => set("host", e.target.value)}
            />
          </label>
          <label>
            Port
            <input
              type="number"
              value={cfg.port ?? 514}
              onChange={(e) => set("port", Number(e.target.value))}
            />
          </label>
          <label>
            Transport
            <select
              value={cfg.transport}
              onChange={(e) => set("transport", e.target.value as Job["transport"])}
            >
              <option value="udp">UDP</option>
              <option value="tcp">TCP (RFC 6587 framing)</option>
              <option value="tls">TLS (RFC 5425)</option>
            </select>
          </label>
          <label>
            Wire format
            <select value={cfg.format ?? ""} onChange={(e) => set("format", e.target.value)}>
              <option value="">Preset default</option>
              <option value="rfc3164">RFC 3164</option>
              <option value="rfc5424">RFC 5424</option>
              <option value="raw">Raw (PRI + payload)</option>
            </select>
          </label>
          {cfg.transport === "tls" && (
            <label className="check">
              <input
                type="checkbox"
                checked={cfg.tlsInsecure ?? false}
                onChange={(e) => set("tlsInsecure", e.target.checked)}
              />
              Skip certificate verification (lab)
            </label>
          )}
        </div>

        <h3>Rate</h3>
        <div className="form-grid">
          <label>
            Events per second
            <input
              type="number"
              step="0.1"
              min="0.01"
              value={cfg.rate ?? 5}
              onChange={(e) => set("rate", Number(e.target.value))}
            />
          </label>
          <label>
            Mode
            <select value={cfg.rateMode} onChange={(e) => set("rateMode", e.target.value)}>
              <option value="steady">Steady</option>
              <option value="jitter">Jitter (±%)</option>
              <option value="burst">Burst</option>
            </select>
          </label>
          {cfg.rateMode === "jitter" && (
            <label>
              Jitter ±%
              <input
                type="number"
                value={cfg.jitterPct ?? 30}
                onChange={(e) => set("jitterPct", Number(e.target.value))}
              />
            </label>
          )}
          {cfg.rateMode === "burst" && (
            <>
              <label>
                Burst ×rate
                <input
                  type="number"
                  value={cfg.burstFactor ?? 5}
                  onChange={(e) => set("burstFactor", Number(e.target.value))}
                />
              </label>
              <label>
                Burst every (s)
                <input
                  type="number"
                  value={cfg.burstEvery ?? 30}
                  onChange={(e) => set("burstEvery", Number(e.target.value))}
                />
              </label>
              <label>
                Burst length (s)
                <input
                  type="number"
                  value={cfg.burstLen ?? 5}
                  onChange={(e) => set("burstLen", Number(e.target.value))}
                />
              </label>
            </>
          )}
          <label>
            Stop after (seconds, 0 = run until stopped)
            <input
              type="number"
              value={cfg.durationSec ?? 0}
              onChange={(e) => set("durationSec", Number(e.target.value))}
            />
          </label>
          <label>
            Stop after (events, 0 = unlimited)
            <input
              type="number"
              value={cfg.maxEvents ?? 0}
              onChange={(e) => set("maxEvents", Number(e.target.value))}
            />
          </label>
        </div>

        <h3>Identity overrides</h3>
        <div className="form-grid">
          <label>
            HOSTNAME field
            <input
              value={cfg.hostname ?? ""}
              placeholder="(preset default)"
              onChange={(e) => set("hostname", e.target.value)}
            />
          </label>
          <label>
            APP-NAME field
            <input
              value={cfg.appname ?? ""}
              placeholder="(preset default)"
              onChange={(e) => set("appname", e.target.value)}
            />
          </label>
          <label className="check">
            <input
              type="checkbox"
              checked={cfg.autostart ?? false}
              onChange={(e) => set("autostart", e.target.checked)}
            />
            Start automatically when syslog-hose boots
          </label>
        </div>

        {samples.length > 0 && (
          <pre className="samples">
            {samples.map((s, i) => (
              <div key={i}>{s}</div>
            ))}
          </pre>
        )}
        {error && <Banner kind="error">{error}</Banner>}
    </Dialog>
  );
}
