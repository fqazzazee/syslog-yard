import { useEffect, useState } from "react";
import { errorText } from "../../../shared/web/src/http";
import { toast } from "../../../shared/web/src/Toast";
import { Badge, Banner, Button, EmptyState, PageHeader } from "../../../shared/web/src/ui";
import { api, type PresetSummary } from "./api";

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

export function PresetsView(props: {
  presets: PresetSummary[];
  readOnly: boolean;
  routeName?: string; // #/presets/<name> deep link
  onOpen: (name: string | null) => void;
  onChanged: () => void;
}) {
  const [selected, setSelected] = useState<string | null>(null);
  const [yaml, setYaml] = useState("");
  const [builtin, setBuiltin] = useState(false);
  const [samples, setSamples] = useState<string[]>([]);
  const [error, setError] = useState("");

  const load = (name: string) => {
    setError("");
    setSamples([]);
    api
      .preset(name)
      .then((p) => {
        setSelected(p.name);
        setYaml(p.yaml);
        setBuiltin(p.builtin);
      })
      .catch((e: unknown) => setError(errorText(e)));
  };

  // The URL names the open preset, so back/forward and shared links work.
  useEffect(() => {
    if (props.routeName && props.routeName !== selected) load(props.routeName);
    if (!props.routeName && selected !== "(new)") {
      setSelected(null);
      setYaml("");
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [props.routeName]);

  const startNew = (base?: string) => {
    setSelected("(new)");
    setBuiltin(false);
    setSamples([]);
    setError("");
    setYaml(base ? base.replace(/^name: .*$/m, "name: my-copy") : SKELETON);
    if (props.routeName) props.onOpen(null);
  };

  const preview = () => {
    setError("");
    api
      .preview({ yaml, count: 8 })
      .then((r) => setSamples(r.samples))
      .catch((e: unknown) => setError(errorText(e)));
  };

  const save = () => {
    setError("");
    api
      .savePreset(yaml)
      .then((r) => {
        toast(`Saved custom preset "${r.name}"`);
        props.onChanged();
        setSelected(r.name);
        setBuiltin(false);
        props.onOpen(r.name);
      })
      .catch((e: unknown) => setError(errorText(e)));
  };

  const remove = () => {
    if (!selected || builtin) return;
    if (!confirm(`Delete custom preset "${selected}"?`)) return;
    api
      .deletePreset(selected)
      .then(() => {
        toast(`Deleted preset "${selected}"`);
        setSelected(null);
        setYaml("");
        props.onChanged();
        props.onOpen(null);
      })
      .catch((e: unknown) => setError(errorText(e)));
  };

  const vendors = [...new Set(props.presets.map((p) => p.vendor))];

  return (
    <>
      <PageHeader
        title="Presets"
        icon="category"
        meta={`${props.presets.length} presets`}
        actions={
          !props.readOnly && (
            <Button variant="primary" icon="add" onClick={() => startNew()}>
              New custom preset
            </Button>
          )
        }
      />
      <div className="page presets">
        <nav className="preset-list" aria-label="Presets">
          {vendors.map((v) => (
            <div key={v} className="preset-group">
              <h2 className="vendor">{v}</h2>
              <ul>
                {props.presets
                  .filter((p) => p.vendor === v)
                  .map((p) => (
                    <li key={p.name}>
                      <a
                        href={`#/presets/${encodeURIComponent(p.name)}`}
                        className={selected === p.name ? "preset-item active" : "preset-item"}
                        aria-current={selected === p.name ? "page" : undefined}
                        title={p.description}
                      >
                        <span className="preset-name">{p.name}</span>
                        <Badge>{p.builtin ? `${p.eventCount} ev` : "custom"}</Badge>
                      </a>
                    </li>
                  ))}
              </ul>
            </div>
          ))}
        </nav>

        <section className="preset-editor" aria-label="Preset editor">
          {selected === null ? (
            <EmptyState icon="category" title="Select a preset">
              Inspect a preset, or create a custom one. Built-ins are read-only — use <strong>Clone to custom</strong>{" "}
              to adapt one. Custom presets can also be dropped into <code>/data/presets/*.yaml</code>.
            </EmptyState>
          ) : (
            <>
              <div className="preset-toolbar">
                <h2>{selected}</h2>
                {builtin && <Badge>built-in · read-only</Badge>}
                <div className="spacer" />
                <Button onClick={preview}>Render 8 samples</Button>
                {builtin ? (
                  !props.readOnly && <Button onClick={() => startNew(yaml)}>Clone to custom</Button>
                ) : (
                  !props.readOnly && (
                    <>
                      <Button variant="primary" onClick={save}>
                        Save
                      </Button>
                      {selected !== "(new)" && (
                        <Button variant="quiet" icon="delete" onClick={remove}>
                          Delete
                        </Button>
                      )}
                    </>
                  )
                )}
              </div>
              <textarea
                className="yaml"
                aria-label={`YAML of ${selected}`}
                value={yaml}
                readOnly={builtin || props.readOnly}
                spellCheck={false}
                onChange={(e) => setYaml(e.target.value)}
              />
              {error && <Banner kind="error">{error}</Banner>}
              {samples.length > 0 && (
                <pre className="samples" tabIndex={0} aria-label="Rendered samples">
                  {samples.map((s, i) => (
                    <div key={i}>{s}</div>
                  ))}
                </pre>
              )}
            </>
          )}
          {selected === null && error && <Banner kind="error">{error}</Banner>}
        </section>
      </div>
    </>
  );
}
