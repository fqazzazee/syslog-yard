import { useState } from "react";
import { api, PresetSummary } from "./api";

const SKELETON = `name: my-appliance
vendor: MyVendor
description: What this device's logs look like
# format: rfc3164 | rfc5424 | raw  (raw = "<PRI>" + template as-is)
format: rfc3164
facility: 16
appname: myapp
events:
  - weight: 80
    severity: 6
    template: >-
      user={{oneOf "alice" "bob"}} src={{randIP "rfc1918"}}:{{randPort}}
      dst={{randIP "public"}}:443 action=allow session={{seq "session"}}
  - weight: 20
    severity: 4
    template: >-
      action=deny src={{randIP "public"}} dst={{randIP "rfc1918"}} port={{randInt 1 1024}}
`;

export function PresetsView(props: { presets: PresetSummary[]; onChanged: () => void }) {
  const [selected, setSelected] = useState<string | null>(null);
  const [yaml, setYaml] = useState("");
  const [builtin, setBuiltin] = useState(false);
  const [samples, setSamples] = useState<string[]>([]);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");

  const open = (name: string) => {
    setError("");
    setNotice("");
    setSamples([]);
    api
      .preset(name)
      .then((p) => {
        setSelected(p.name);
        setYaml(p.yaml);
        setBuiltin(p.builtin);
      })
      .catch((e: Error) => setError(e.message));
  };

  const startNew = (base?: string) => {
    setSelected("(new)");
    setBuiltin(false);
    setSamples([]);
    setError("");
    setNotice("");
    setYaml(base ? base.replace(/^name: .*$/m, "name: my-copy") : SKELETON);
  };

  const preview = () => {
    setError("");
    api
      .preview({ yaml, count: 8 })
      .then((r) => setSamples(r.samples))
      .catch((e: Error) => setError(e.message));
  };

  const save = () => {
    setError("");
    api
      .savePreset(yaml)
      .then((r) => {
        setNotice(`Saved custom preset "${r.name}"`);
        props.onChanged();
        setSelected(r.name);
        setBuiltin(false);
      })
      .catch((e: Error) => setError(e.message));
  };

  const remove = () => {
    if (!selected || builtin) return;
    if (!confirm(`Delete custom preset "${selected}"?`)) return;
    api
      .deletePreset(selected)
      .then(() => {
        setSelected(null);
        setYaml("");
        props.onChanged();
      })
      .catch((e: Error) => setError(e.message));
  };

  const vendors = [...new Set(props.presets.map((p) => p.vendor))];

  return (
    <div className="presets">
      <aside>
        <button className="primary wide" onClick={() => startNew()}>
          + New custom preset
        </button>
        {vendors.map((v) => (
          <div key={v}>
            <div className="vendor">{v}</div>
            {props.presets
              .filter((p) => p.vendor === v)
              .map((p) => (
                <button
                  key={p.name}
                  className={selected === p.name ? "preset-item active" : "preset-item"}
                  onClick={() => open(p.name)}
                  title={p.description}
                >
                  {p.name}
                  <span className="chip dim">{p.builtin ? `${p.eventCount} ev` : "custom"}</span>
                </button>
              ))}
          </div>
        ))}
      </aside>

      <section className="preset-editor">
        {selected === null ? (
          <div className="empty">
            Select a preset to inspect it, or create a custom one. Built-ins are read-only —
            use <strong>Clone</strong> to adapt one. Custom presets can also be dropped into{" "}
            <code>/data/presets/*.yaml</code>.
          </div>
        ) : (
          <>
            <div className="toolbar">
              <strong>{selected}</strong>
              {builtin && <span className="chip">built-in (read-only)</span>}
              <div className="spacer" />
              <button onClick={preview}>Render 8 samples</button>
              {builtin ? (
                <button onClick={() => startNew(yaml)}>Clone to custom</button>
              ) : (
                <>
                  <button className="primary" onClick={save}>
                    Save
                  </button>
                  {selected !== "(new)" && (
                    <button className="quiet" onClick={remove}>
                      Delete
                    </button>
                  )}
                </>
              )}
            </div>
            <textarea
              className="yaml"
              value={yaml}
              readOnly={builtin}
              spellCheck={false}
              onChange={(e) => setYaml(e.target.value)}
            />
            {error && <div className="form-error">{error}</div>}
            {notice && <div className="form-notice">{notice}</div>}
            {samples.length > 0 && (
              <pre className="samples">
                {samples.map((s, i) => (
                  <div key={i}>{s}</div>
                ))}
              </pre>
            )}
          </>
        )}
      </section>
    </div>
  );
}
