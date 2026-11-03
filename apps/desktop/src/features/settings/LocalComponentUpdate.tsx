import * as Dialog from "@radix-ui/react-dialog";
import { DialogContent } from "../../components/DialogContent";
import { Busy, OperationResult } from "../../components/OperationResult";
import { useEffect, useState } from "react";
import { api } from "../../api";
import { InlineError } from "../../components/ui";
import { errorMessage } from "../../lib/errors";
import { useInfoHint } from "../../components/InfoHint";
import { t } from "../../i18n";

export function LocalComponentUpdate({
  open,
  onOpenChange,
  onCheckUpdates,
  disconnected,
  onUpdated,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onCheckUpdates: () => void;
  disconnected: boolean;
  onUpdated: () => Promise<void>;
}) {
  const [status, setStatus] = useState<{ install_available: boolean; update_required: boolean } | null>(null);
  const [loading, setLoading] = useState(false);
  const [installing, setInstalling] = useState(false);
  const [error, setError] = useState<{ message: string; retry?: () => void } | null>(null);
  const [updated, setUpdated] = useState(false);
  const [attempt, setAttempt] = useState(0);
  const [bundledHint, bundledPanel] = useInfoHint(t("release.component.bundledInfo"), t("release.component.bundledInfoLabel"));
  useEffect(() => {
    if (!open) return;
    let active = true;
    setStatus(null); setError(null); setUpdated(false); setLoading(true);
    api.localComponentUpdateStatus().then((value) => {
      if (active) setStatus(value);
    }).catch((reason) => {
      if (active) setError({ message: errorMessage(reason, t("release.component.errorCheck")), retry: () => setAttempt((value) => value + 1) });
    }).finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, [open, attempt]);
  async function install() {
    if (installing || !disconnected || !status?.install_available) return;
    setInstalling(true); setError(null);
    try {
      await api.installLocalVpnComponent();
      setStatus({ install_available: true, update_required: false });
      setUpdated(true);
      await onUpdated();
    } catch (reason) {
      // The footer's Update button is the retry.
      setError({ message: errorMessage(reason, t("release.component.errorInstall")) });
    } finally { setInstalling(false); }
  }
  const updatable = Boolean(status?.install_available && status.update_required);
  const footer = updated || (status?.install_available && !status.update_required)
    ? <button className="primary-button" type="button" onClick={() => onOpenChange(false)}>{t("common.action.done")}</button>
    : updatable
      ? <button className="primary-button" type="button" disabled={installing || !disconnected} onClick={() => void install()}>
          {installing ? <Busy label={t("release.component.waiting")} /> : t("release.component.update")}
        </button>
      : status
        ? <button className="primary-button" type="button" onClick={() => { onOpenChange(false); onCheckUpdates(); }}>{t("release.component.openUpdates")}</button>
        : null;
  return (
    <Dialog.Root open={open} onOpenChange={(next) => { if (!installing) onOpenChange(next); }}>
      <Dialog.Portal>
        <Dialog.Overlay className="dialog-overlay" />
        <DialogContent className="dialog-content local-component-dialog"
          heading={t("release.component.title")}
          description={t("release.component.description")}
          closeDisabled={installing} closeLabel={t("release.component.close")}
          footerNote={updatable && !disconnected && !installing ? t("release.component.disconnectFirst") : null}
          footer={footer}>
          {error && <InlineError message={error.message} onRetry={error.retry} retryDisabled={installing || loading} />}
          {loading && <p className="settings-note" role="status"><Busy label={t("release.component.checking")} /></p>}
          {/* Once updated, the result replaces the instructions it would otherwise sit under. */}
          {updated ? <OperationResult title={t("release.component.updated")} />
            : status?.install_available ? <>
              <p className="settings-note">{t("release.component.bundled")}{bundledHint}</p>
              {bundledPanel}
              {!status.update_required && <p role="status">{t("release.component.current")}</p>}
            </> : status && <>
              <ol className="maintenance-plan">
                <li>{t("release.component.stepInstall")}</li>
                <li>{t("release.component.stepApprove")}</li>
                <li>{t("release.component.stepReconnect")}</li>
              </ol>
              <p className="settings-note">{t("release.component.serverNote")}</p>
            </>}
        </DialogContent>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
