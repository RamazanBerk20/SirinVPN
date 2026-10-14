import { DialogContent } from "../../components/DialogContent";
import * as Dialog from "@radix-ui/react-dialog";
import { ArrowClockwise, Check, Key, Warning, } from "@phosphor-icons/react";
import { useEffect, useState } from "react";
import { api } from "../../api";
import { type KeyRotationResult, type ServerProfile } from "../../types";
import { InlineError } from "../../components/ui";
import { errorMessage } from "../../lib/errors";
import { t } from "../../i18n";

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
      setError(errorMessage(reason, t("settings.keyRotation.failed")));
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
              ? t("settings.keyRotation.doneTitle")
              : pending
                ? t("settings.keyRotation.resumeTitle")
                : t("settings.keyRotation.title")}</>}
          description={<>{t("settings.keyRotation.description")}</>}
          closeDisabled={busy} closeLabel={t("common.action.close")}>

          {result ? (
            <div className="backup-success key-rotation-success">
              <span>
                <Check size={26} weight="bold" />
              </span>
              <h3>{t("settings.keyRotation.done.title")}</h3>
              <p>{t("settings.keyRotation.done.summary")}</p>
              <code>{result.identity_fingerprint}</code>
              <button
                className="primary-button"
                onClick={() => onOpenChange(false)}
              >
                {t("common.action.done")}
              </button>
            </div>
          ) : busy ? (
            <div className="uninstall-progress key-rotation-progress">
              <ArrowClockwise className="spin" size={26} />
              <strong>
                {pending
                  ? t("settings.keyRotation.progress.resuming")
                  : t("settings.keyRotation.progress.rotating")}
              </strong>
              <p>{t("settings.keyRotation.progress.summary")}</p>
            </div>
          ) : (
            <div className="uninstall-fingerprint key-rotation-confirmation">
              <Key size={28} weight="duotone" />
              <h3>
                {pending
                  ? t("settings.keyRotation.confirmation.resumeTitle")
                  : t("settings.keyRotation.confirmation.title")}
              </h3>
              <div className="warning-note replacement-warning">
                <Warning size={18} weight="fill" />
                <span>
                  {pending
                    ? t("settings.keyRotation.confirmation.resumeWarning")
                    : t("settings.keyRotation.confirmation.warning")}
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
                  <strong>{t("settings.keyRotation.confirmation.accept")}</strong>
                  <small>{t("settings.keyRotation.confirmation.acceptHint")}</small>
                </span>
              </label>
              {error ? <InlineError message={error} /> : null}
              <button
                className="primary-button"
                disabled={!confirmed}
                onClick={() => void rotate()}
              >
                {pending
                  ? t("settings.keyRotation.confirmation.resume")
                  : t("settings.keyRotation.confirmation.rotate")}
              </button>
            </div>
          )}
        </DialogContent>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
