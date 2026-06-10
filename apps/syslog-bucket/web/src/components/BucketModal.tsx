import { useState } from "react";
import { createBucket, deleteBucket, updateBucket } from "./../api";
import type { Bucket, Cond, Tag } from "./../types";
import ConditionBuilder from "./ConditionBuilder";
import Modal from "./Modal";

interface Props {
  bucket: Bucket | null; // null = create
  tags: Tag[];
  onClose: (changed: boolean) => void;
}

export default function BucketModal({ bucket, tags, onClose }: Props) {
  const [name, setName] = useState(bucket?.name ?? "");
  const [description, setDescription] = useState(bucket?.description ?? "");
  const [condition, setCondition] = useState<Cond>(bucket?.condition ?? {});
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const save = async () => {
    setBusy(true);
    setError(null);
    try {
      if (bucket) {
        await updateBucket({ ...bucket, name, description, condition });
      } else {
        await createBucket({ name, description, condition, position: 0 });
      }
      onClose(true);
    } catch (e) {
      setError(String(e));
      setBusy(false);
    }
  };

  const remove = async () => {
    if (!bucket || !confirm(`Delete bucket "${bucket.name}"? Entries are not affected.`)) return;
    setBusy(true);
    try {
      await deleteBucket(bucket.id);
      onClose(true);
    } catch (e) {
      setError(String(e));
      setBusy(false);
    }
  };

  return (
    <Modal title={bucket ? "Edit bucket" : "New bucket"} onClose={() => onClose(false)}>
      <label>
        Name
        <input value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. Firewall denies" autoFocus />
      </label>
      <label>
        Description
        <input value={description} onChange={(e) => setDescription(e.target.value)} placeholder="optional" />
      </label>
      <label>Show entries matching</label>
      <ConditionBuilder value={condition} onChange={setCondition} tags={tags} />
      {error && <div className="error">{error}</div>}
      <div className="modal-foot">
        {bucket && (
          <button className="danger" disabled={busy} onClick={() => void remove()}>
            Delete
          </button>
        )}
        <button className="primary" disabled={busy || !name.trim()} onClick={() => void save()}>
          {bucket ? "Save" : "Create"}
        </button>
      </div>
    </Modal>
  );
}
