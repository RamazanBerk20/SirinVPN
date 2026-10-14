import * as Dialog from "@radix-ui/react-dialog";
import { DialogContent } from "../../components/DialogContent";
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
  const [error, setError] = useState("");
  const [updated, setUpdated] = useState(false);
  const [bundledHint, bundledPanel] = useInfoHint(t("release.component.bundledInfo"), t("release.component.bundledInfoLabel"));
  useEffect(() => {
    if (!open) return;
    let active = true;
    setStatus(null); setError(""); setUpdated(false); setLoading(true);
    api.localComponentUpdateStatus().then((value) => {
      if (active) setStatus(value);
    }).catch((reason) => {
      if (active) setError(errorMessage(reason, t("release.component.errorCheck")));
    }).finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, [open]);
  async function install() {
    if (installing || !disconnected || !status?.install_available) return;
    setInstalling(true); setError("");
    try {
      await api.installLocalVpnComponent();
      setStatus({ install_available: true, update_required: false });
      setUpdated(true);
      await onUpdated();
    } catch (reason) {
      setError(errorMessage(reason, t("release.component.errorInstall")));
    } finally { setInstalling(false); }
  }
  return (
    <Dialog.Root open={open} onOpenChange={(next) => { if (!installing) onOpenChange(next); }}>
      <Dialog.Portal>
        <Dialog.Overlay className="dialog-overlay" />
        <DialogContent className="dialog-content"
          heading={t("release.component.title")}
          description={t("release.component.description")}
          closeDisabled={installing} closeLabel={t("release.component.close")}>
          {loading && <p className="settings-note" role="status">{t("release.component.checking")}</p>}
          {status?.install_available ? <>
            <p className="settings-note">{t("release.component.bundled")}{bundledHint}</p>
            {bundledPanel}
            {!status.update_required && <p role="status">{updated ? t("release.component.updated") : t("release.component.current")}</p>}
            {status.update_required && <>
              {!disconnected && <p className="settings-note">{t("release.component.disconnectFirst")}</p>}
              <button className="primary-button" disabled={installing || !disconnected} onClick={() => void install()}>
                {installing ? t("release.component.waiting") : t("release.component.update")}
              </button>
            </>}
          </> : status && <>
          <ol className="maintenance-plan">
            <li>{t("release.component.stepInstall")}</li>
            <li>{t("release.component.stepApprove")}</li>
            <li>{t("release.component.stepReconnect")}</li>
          </ol>
          <p className="settings-note">{t("release.component.serverNote")}</p>
          <button
            className="primary-button"
            onClick={() => {
              onOpenChange(false);
              onCheckUpdates();
            }}
          >
            {t("release.component.openUpdates")}
          </button>
          </>}
          <InlineError message={error} />
        </DialogContent>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
