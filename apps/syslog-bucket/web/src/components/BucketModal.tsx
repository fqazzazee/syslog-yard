import { useEffect, useState } from "react";
import { createBucket, deleteBucket, fetchBucketShares, fetchUsers, putBucketShares, updateBucket } from "./../api";
import type { Bucket, BucketShare, Cond, Tag, User } from "./../types";
import ConditionBuilder from "./ConditionBuilder";
import Modal from "./Modal";

interface Props {
  bucket: Bucket | null; // null = create
  tags: Tag[];
  me: User;
  onClose: (changed: boolean) => void;
}

export default function BucketModal({ bucket, tags, me, onClose }: Props) {
  const [name, setName] = useState(bucket?.name ?? "");
  const [description, setDescription] = useState(bucket?.description ?? "");
  const [condition, setCondition] = useState<Cond>(bucket?.condition ?? {});
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  // Sharing is owner/admin territory (analysts for ownerless yard buckets);
  // the server enforces the same rule.
  const canManage =
    !!bucket &&
    (me.role === "admin" || bucket.owner_id === me.id || (!bucket.owner_id && me.role === "analyst"));
  const [users, setUsers] = useState<User[]>([]);
  const [shares, setShares] = useState<BucketShare[] | null>(null);

  useEffect(() => {
    if (!canManage || !bucket) return;
    Promise.all([fetchUsers(), fetchBucketShares(bucket.id)])
      .then(([u, sh]) => {
        setUsers(u);
        setShares(sh);
      })
      .catch((e) => setError(String(e)));
  }, [canManage, bucket]);

  const shareFor = (userId: number) => shares?.find((s) => s.user_id === userId);
  const setShare = (u: User, visible: boolean, canEdit: boolean) => {
    if (!shares) return;
    const rest = shares.filter((s) => s.user_id !== u.id);
    setShares(visible ? [...rest, { user_id: u.id, username: u.username, can_edit: canEdit }] : rest);
  };

  const save = async () => {
    setBusy(true);
    setError(null);
    try {
      if (bucket) {
        await updateBucket({ ...bucket, name, description, condition });
        if (canManage && shares) await putBucketShares(bucket.id, shares);
      } else {
        await createBucket({
          name,
          description,
          condition,
          position: 0,
          can_edit: true,
          shared: false,
        });
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

      {canManage && shares && (
        <>
          <label>Sharing</label>
          <div className="share-list">
            {users.filter((u) => u.id !== me.id && u.id !== bucket?.owner_id && !u.disabled).map((u) => {
              const sh = shareFor(u.id);
              return (
                <div className="cond-row" key={u.id}>
                  <label className="check">
                    <input
                      type="checkbox"
                      checked={!!sh}
                      onChange={(e) => setShare(u, e.target.checked, sh?.can_edit ?? false)}
                    />
                    {u.username}
                    {u.display_name && <span className="hint-inline">({u.display_name})</span>}
                  </label>
                  <label className="check share-edit">
                    <input
                      type="checkbox"
                      disabled={!sh || u.role === "viewer"}
                      checked={!!sh?.can_edit && u.role !== "viewer"}
                      onChange={(e) => setShare(u, true, e.target.checked)}
                    />
                    can edit
                  </label>
                </div>
              );
            })}
            {users.filter((u) => u.id !== me.id && u.id !== bucket?.owner_id && !u.disabled).length === 0 && (
              <p className="hint">No other users yet — an admin can add them under Users.</p>
            )}
          </div>
        </>
      )}
      {!bucket && <p className="hint">You can share the bucket with other users after creating it.</p>}

      {error && <div className="error">{error}</div>}
      <div className="modal-foot">
        {bucket && canManage && (
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
