import { DialogContent } from "../../components/DialogContent";
import * as Dialog from "@radix-ui/react-dialog";
import { ArrowClockwise, Check, Key, Warning, } from "@phosphor-icons/react";
import { useEffect, useState } from "react";
import { api } from "../../api";
import { type KeyRotationResult, type ServerProfile } from "../../types";
import { InlineError } from "../../components/ui";
import { errorMessage } from "../../lib/errors";

export function KeyRotationDialog({
  profile,
  open,
  onOpenChange,
  pending,
  onCompleted,
  onPendingChanged,
}: {
  profile: ServerProfile;
  open: boolean;
  onOpenChange: (open: boolean) => void;
  pending: boolean;
  onCompleted: () => Promise<void>;
  onPendingChanged: () => Promise<void>;
}) {
  const [confirmed, setConfirmed] = useState(false);
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<KeyRotationResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!open) {
      setConfirmed(false);
      setBusy(false);
      setResult(null);
      setError(null);
    }
  }, [open]);

  const changeOpen = (next: boolean) => {
    if (!next && busy) return;
    onOpenChange(next);
  };

  const rotate = async () => {
    if (!confirmed) return;
    setBusy(true);
    setError(null);
    try {
      const completed = await api.rotateDeviceKeys(profile.id, true);
      setResult(completed);
      await onCompleted();
    } catch (reason) {
      setConfirmed(false);
      setError(
        errorMessage(
          reason,
          "Key rotation stopped safely. If a transition was already staged, use Resume keys after network access returns.",
        ),
      );
      await onPendingChanged();
    } finally {
      setBusy(false);
    }
  };

  return (
    <Dialog.Root open={open} onOpenChange={changeOpen}>
      <Dialog.Portal>
        <Dialog.Overlay className="dialog-overlay" />
        <DialogContent className="dialog-content remove-server-dialog key-rotation-dialog"
          heading={<>{result
              ? "Device keys rotated"
              : pending
                ? "Resume key rotation"
                : "Rotate this device's keys"}</>}
          description={<>Generate fresh WireGuard and management keys locally without
            changing this device's access, address, or name.</>}
          closeDisabled={busy} closeLabel="Close">

          {result ? (
            <div className="backup-success key-rotation-success">
              <span>
                <Check size={26} weight="bold" />
              </span>
              <h3>Fresh identity is active</h3>
              <p>
                The VPS accepted the new public keys, the tunnel reconnected,
                and the previous private identity was removed locally.
              </p>
              <code>{result.identity_fingerprint}</code>
              <button
                className="primary-button"
                onClick={() => onOpenChange(false)}
              >
                Done
              </button>
            </div>
          ) : busy ? (
            <div className="uninstall-progress key-rotation-progress">
              <ArrowClockwise className="spin" size={26} />
              <strong>
                {pending
                  ? "Recovering the staged transition"
                  : "Rotating both device keys"}
              </strong>
              <p>
                The tunnel briefly reconnects. Keep the app open while the new
                identity is verified and the old local keys are removed.
              </p>
            </div>
          ) : (
            <div className="uninstall-fingerprint key-rotation-confirmation">
              <Key size={28} weight="duotone" />
              <h3>
                {pending
                  ? "A recoverable transition is waiting"
                  : "Replace only this device's identity"}
              </h3>
              <div className="warning-note replacement-warning">
                <Warning size={18} weight="fill" />
                <span>
                  {pending
                    ? "SirinVPN retained the staged local keys so it can determine whether the VPS committed the change. Resume instead of deleting or recreating this profile."
                    : "Private keys are generated on this computer and never sent to the VPS. Existing members, other devices, permissions, invitations, and the VPS identity remain unchanged."}
                </span>
              </div>
              <label
                className={`replacement-option ${confirmed ? "selected" : ""}`}
              >
                <input
                  type="checkbox"
                  checked={confirmed}
                  onChange={(event) => setConfirmed(event.target.checked)}
                />
                <span>
                  <strong>
                    I understand the tunnel will briefly reconnect
                  </strong>
                  <small>
                    Persistent protection is restored after the new identity
                    passes verification.
                  </small>
                </span>
              </label>
              {error ? <InlineError message={error} /> : null}
              <button
                className="primary-button"
                disabled={!confirmed}
                onClick={() => void rotate()}
              >
                {pending ? "Resume safely" : "Rotate both keys"}
              </button>
            </div>
          )}
        </DialogContent>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
