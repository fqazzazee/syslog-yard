import { useState } from "react";
import { changePassword } from "./../api";
import type { User } from "./../types";
import Modal from "./Modal";

interface Props {
  me: User;
  onClose: () => void;
}

export default function AccountModal({ me, onClose }: Props) {
  const [oldPw, setOldPw] = useState("");
  const [newPw, setNewPw] = useState("");
  const [confirmPw, setConfirmPw] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState(false);

  const save = async () => {
    setError(null);
    if (newPw !== confirmPw) {
      setError("New passwords do not match");
      return;
    }
    try {
      await changePassword(oldPw, newPw);
      setDone(true);
      setTimeout(onClose, 1200);
    } catch (e) {
      setError(String(e instanceof Error ? e.message : e));
    }
  };

  return (
    <Modal title={`Account — ${me.username}`} onClose={onClose}>
      {me.has_password ? (
        <>
          <label>
            Current password
            <input type="password" value={oldPw} onChange={(e) => setOldPw(e.target.value)} autoFocus />
          </label>
          <label>
            New password (min 8 characters)
            <input type="password" value={newPw} onChange={(e) => setNewPw(e.target.value)} />
          </label>
          <label>
            Repeat new password
            <input type="password" value={confirmPw} onChange={(e) => setConfirmPw(e.target.value)} />
          </label>
          {error && <div className="error">{error}</div>}
          {done && <div className="notice">Password changed — other sessions were signed out.</div>}
          <div className="modal-foot">
            <button className="primary" disabled={!oldPw || newPw.length < 8 || done} onClick={() => void save()}>
              Change password
            </button>
          </div>
        </>
      ) : (
        <p className="hint">This account signs in via OIDC; manage its password at your identity provider.</p>
      )}
    </Modal>
  );
}
