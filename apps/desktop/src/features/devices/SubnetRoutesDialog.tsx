import * as Dialog from "@radix-ui/react-dialog";
import { useState } from "react";
import { api } from "../../api";
import { DialogContent } from "../../components/DialogContent";
import { InlineError } from "../../components/ui";
import { errorMessage } from "../../lib/errors";
import type { DeviceSummary } from "../../types";
import { t } from "../../i18n";

/** The VPS validates the ranges; this only splits the list the Owner typed. */
export const parseRoutes = (text: string) => text.split(/[\s,]+/).filter(Boolean);

export function SubnetRoutesDialog({ serverId, device, onClose, onSaved }: {
  serverId: string; device: DeviceSummary; onClose: () => void; onSaved: () => Promise<void>;
}) {
  const [draft, setDraft] = useState(() => (device.subnet_routes ?? []).join("\n"));
  const [busy, setBusy] = useState(false), [error, setError] = useState<string | null>(null);
  const save = async () => {
    setBusy(true); setError(null);
    try {
      await api.updateDeviceSubnetRoutes(serverId, device.id, parseRoutes(draft));
      await onSaved(); onClose();
    } catch (reason) { setError(errorMessage(reason, t("devices.localNetworks.saveFailed"))); }
    finally { setBusy(false); }
  };
  return <Dialog.Root open onOpenChange={(open) => { if (!open && !busy) onClose(); }}>
    <Dialog.Portal><Dialog.Overlay className="dialog-overlay" /><DialogContent className="dialog-content invitation-dialog"
          heading={<>{t("devices.localNetworks.title", { name: device.name })}</>}
          description={<>{t("devices.localNetworks.description", { name: device.name })}</>}
          closeDisabled={busy} closeLabel={t("common.action.close")}>
      <form className="invite-form" onSubmit={(event) => { event.preventDefault(); void save(); }}>
        <label className="route-list-field">
          <span>{t("devices.localNetworks.label")}</span>
          <textarea value={draft} onChange={(event) => setDraft(event.target.value)} placeholder="192.168.1.0/24" rows={3} disabled={busy} />
          <small>{t("devices.localNetworks.hint")}</small>
        </label>
        <p className="settings-note">{t("devices.localNetworks.linux", { name: device.name })}</p>
        <p className="settings-note">{t("devices.localNetworks.apply")}</p>
        {error && <InlineError message={error} />}
        <button className="primary-button" type="submit" disabled={busy}>{busy ? t("common.state.saving") : t("devices.localNetworks.save")}</button>
      </form>
    </DialogContent></Dialog.Portal>
  </Dialog.Root>;
}
