import { DialogContent } from "../../components/DialogContent";
import { HashValue } from "../../components/CopyValue";
import { ConfirmationRow } from "../../components/ConfirmationRow";
import { OperationProgress, OperationResult } from "../../components/OperationResult";
import * as Dialog from "@radix-ui/react-dialog";
import { Info, Warning } from "@phosphor-icons/react";
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
  addsPresharedKey = false,
  onCompleted,
  onPendingChanged,
}: {
  profile: ServerProfile;
  open: boolean;
  onOpenChange: (open: boolean) => void;
  pending: boolean;
  addsPresharedKey?: boolean;
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
      // The consent still holds, so trying again is one click.
      setError(errorMessage(reason, t("settings.keyRotation.failed")));
      await onPendingChanged();
    } finally {
      setBusy(false);
    }
  };

  const action = error ? pending ? t("settings.keyRotation.confirmation.resume") : t("common.action.retry")
    : pending ? t("settings.keyRotation.confirmation.resume") : t("settings.keyRotation.confirmation.rotate");

  return (
    <Dialog.Root open={open} onOpenChange={changeOpen}>
      <Dialog.Portal>
        <Dialog.Overlay className="dialog-overlay" />
        <DialogContent className="dialog-content remove-server-dialog key-rotation-dialog"
          heading={pending && !result ? t("settings.keyRotation.resumeTitle") : t("settings.keyRotation.title")}
          description={result ? t("settings.keyRotation.doneTitle")
            : t(addsPresharedKey && !pending ? "settings.keyRotation.presharedKeyDescription" : "settings.keyRotation.description")}
          closeDisabled={busy} closeLabel={t("common.action.close")}
          footerNote={!result && !busy && !confirmed ? t("vps.rotation.confirmFirst") : null}
          footer={busy ? null : result
            ? <button className="primary-button" type="button" onClick={() => onOpenChange(false)}>{t("common.action.done")}</button>
            : <>
              <button className="secondary-button" type="button" onClick={() => changeOpen(false)}>{t("common.action.cancel")}</button>
              <button className="primary-button" type="button" disabled={!confirmed} onClick={() => void rotate()}>{action}</button>
            </>}>

          {result ? (
            <OperationResult title={t("settings.keyRotation.done.title")}>
              <p>{t("settings.keyRotation.done.summary")}</p>
              <HashValue label={t("vps.rotation.fingerprint")} value={result.identity_fingerprint} />
            </OperationResult>
          ) : busy ? (
            <OperationProgress
              title={pending ? t("settings.keyRotation.progress.resuming") : t("settings.keyRotation.progress.rotating")}
              note={t("settings.keyRotation.progress.summary")} />
          ) : (
            <div className="key-rotation-confirmation">
              {error ? <>
                <InlineError message={error} />
                {/* Whether the old keys still work is the first thing to know after a failure. */}
                <p className="rotation-outcome">{pending ? t("vps.rotation.interrupted") : t("vps.rotation.unchanged")}</p>
              </> : null}
              <h3>
                {pending
                  ? t("settings.keyRotation.confirmation.resumeTitle")
                  : t("settings.keyRotation.confirmation.title")}
              </h3>
              {pending
                ? <div className="warning-note replacement-warning"><Warning size={18} weight="fill" /><span>{t("settings.keyRotation.confirmation.resumeWarning")}</span></div>
                : <div className="info-note"><Info size={18} weight="fill" /><span>{t("settings.keyRotation.confirmation.warning")}</span></div>}
              <ConfirmationRow checked={confirmed} onChange={setConfirmed}>
                <strong>{t("settings.keyRotation.confirmation.accept")}</strong>
                <small>{t("settings.keyRotation.confirmation.acceptHint")}</small>
              </ConfirmationRow>
            </div>
          )}
        </DialogContent>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
