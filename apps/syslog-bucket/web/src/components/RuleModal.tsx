import { useState } from "react";
import { applyRule, createRule, deleteRule, updateRule } from "./../api";
import type { Action, Cond, Rule, Tag } from "./../types";
import { PRIORITY_NAMES } from "./../types";
import ConditionBuilder from "./ConditionBuilder";
import Modal from "./Modal";

interface Props {
  rule: Rule | null; // null = create
  tags: Tag[];
  onClose: (changed: boolean) => void;
}

export default function RuleModal({ rule, tags, onClose }: Props) {
  const [name, setName] = useState(rule?.name ?? "");
  const [enabled, setEnabled] = useState(rule?.enabled ?? true);
  const [condition, setCondition] = useState<Cond>(rule?.condition ?? {});
  const [actions, setActions] = useState<Action[]>(rule?.actions ?? [{ type: "tag", tag_id: tags[0]?.id }]);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const patchAction = (i: number, patch: Partial<Action>) =>
    setActions(actions.map((a, j) => (j === i ? { ...a, ...patch } : a)));

  const save = async (): Promise<Rule | null> => {
    setBusy(true);
    setError(null);
    try {
      let saved: Rule;
      if (rule) {
        saved = { ...rule, name, enabled, condition, actions };
        await updateRule(saved);
      } else {
        saved = await createRule({ name, enabled, condition, actions, position: 0 });
      }
      return saved;
    } catch (e) {
      setError(String(e));
      setBusy(false);
      return null;
    }
  };

  const saveAndClose = async () => {
    if (await save()) onClose(true);
  };

  // Save first so history sees exactly what future entries will (PLAN §5).
  const saveAndApply = async () => {
    const saved = await save();
    if (!saved) return;
    try {
      const { affected } = await applyRule(saved.id);
      setNotice(`Applied to history: ${affected} change${affected === 1 ? "" : "s"}.`);
      setBusy(false);
    } catch (e) {
      setError(String(e));
      setBusy(false);
    }
  };

  const remove = async () => {
    if (!rule || !confirm(`Delete rule "${rule.name}"? Tags it already applied stay.`)) return;
    setBusy(true);
    try {
      await deleteRule(rule.id);
      onClose(true);
    } catch (e) {
      setError(String(e));
      setBusy(false);
    }
  };

  return (
    <Modal title={rule ? "Edit rule" : "New rule"} onClose={() => onClose(rule !== null)}>
      <label>
        Name
        <input value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. Tag auth failures" autoFocus />
      </label>
      <label className="check">
        <input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} />
        Enabled for incoming entries
      </label>

      <label>When an entry matches</label>
      <ConditionBuilder value={condition} onChange={setCondition} tags={tags} />

      <label>Do</label>
      {actions.map((a, i) => (
        <div className="cond-row" key={i}>
          <select value={a.type} onChange={(e) => patchAction(i, { type: e.target.value as Action["type"], tag_id: tags[0]?.id, priority: 2 })}>
            <option value="tag">Add tag</option>
            <option value="set_priority">Set priority</option>
            <option value="suppress">Suppress</option>
          </select>
          {a.type === "tag" && (
            <select value={a.tag_id ?? 0} onChange={(e) => patchAction(i, { tag_id: Number(e.target.value) })}>
              {tags.map((t) => (
                <option key={t.id} value={t.id}>
                  {t.name}
                </option>
              ))}
            </select>
          )}
          {a.type === "set_priority" && (
            <select value={a.priority ?? 0} onChange={(e) => patchAction(i, { priority: Number(e.target.value) })}>
              {PRIORITY_NAMES.map((p, n) => (
                <option key={n} value={n}>
                  {p}
                </option>
              ))}
            </select>
          )}
          {a.type === "suppress" && <span className="hint">hidden from views, kept in storage</span>}
          <button type="button" className="linkish" onClick={() => setActions(actions.filter((_, j) => j !== i))}>
            ✕
          </button>
        </div>
      ))}
      <button type="button" className="linkish" onClick={() => setActions([...actions, { type: "tag", tag_id: tags[0]?.id }])}>
        + action
      </button>

      {error && <div className="error">{error}</div>}
      {notice && <div className="notice">{notice}</div>}
      <div className="modal-foot">
        {rule && (
          <button className="danger" disabled={busy} onClick={() => void remove()}>
            Delete
          </button>
        )}
        <button disabled={busy || !name.trim() || actions.length === 0} onClick={() => void saveAndApply()}>
          Save + run on history
        </button>
        <button className="primary" disabled={busy || !name.trim() || actions.length === 0} onClick={() => void saveAndClose()}>
          Save
        </button>
      </div>
    </Modal>
  );
}
