import * as Dialog from "@radix-ui/react-dialog";
import { ArrowClockwise } from "@phosphor-icons/react";
import { useId, useState } from "react";
import { api } from "../../api";
import { CopyButton } from "../../components/CopyButton";
import { DialogContent } from "../../components/DialogContent";
import { notify } from "../../components/Toasts";
import { Field, InlineError } from "../../components/ui";
import { errorMessage } from "../../lib/errors";
import { hostBitFix, invalidLocalNetworks } from "../../lib/cidr";
import { SettingsDisclosure } from "../settings/SettingsParts";
import type { DeviceSummary } from "../../types";
import { t } from "../../i18n";

/** Splits the list the Owner typed; the VPS validates the ranges again. */
export const parseRoutes = (text: string) => text.split(/[\s,]+/).filter(Boolean);
/** A shell command, the same in every language. */
const FORWARDING_COMMAND = "sudo sysctl -w net.ipv4.ip_forward=1";

export function SubnetRoutesDialog({ serverId, device, onClose, onSaved }: {
  serverId: string; device: DeviceSummary; onClose: () => void; onSaved: () => Promise<void>;
}) {
  const form = useId();
  const [draft, setDraft] = useState(() => (device.subnet_routes ?? []).join("\n"));
  const [busy, setBusy] = useState(false), [error, setError] = useState<string | null>(null);
  // Lines as typed, so "not a network" is reported once rather than word by word.
  const invalid = draft.split("\n").map((line) => line.trim()).filter((line) => line && invalidLocalNetworks(parseRoutes(line)).length > 0);
  const fix = hostBitFix(invalid, (network) => invalidLocalNetworks([network]).length === 0);
  const save = async () => {
    if (invalid.length || busy) return;
    setBusy(true); setError(null);
    try {
      const routes = parseRoutes(draft);
      await api.updateDeviceSubnetRoutes(serverId, device.id, routes);
      notify(t(routes.length ? "devices.notice.networksSaved" : "devices.notice.networksCleared", { name: device.name }));
      await onSaved(); onClose();
    } catch (reason) { setError(errorMessage(reason, t("devices.localNetworks.saveFailed"))); }
    finally { setBusy(false); }
  };
  return <Dialog.Root open onOpenChange={(open) => { if (!open && !busy) onClose(); }}>
    <Dialog.Portal><Dialog.Overlay className="dialog-overlay" /><DialogContent className="dialog-content invitation-dialog"
          heading={<>{t("devices.localNetworks.title", { name: device.name })}</>}
          description={<>{t("devices.localNetworks.description", { name: device.name })}</>}
          closeDisabled={busy} closeLabel={t("common.action.close")}
          footer={<div className="dialog-commit">
            <button className="primary-button" type="submit" form={form} disabled={busy || invalid.length > 0}>
              {busy && <ArrowClockwise className="spin" size={17} />}{busy ? t("common.state.saving") : t("devices.localNetworks.save")}
            </button>
          </div>}>
      <form id={form} className="invite-form" onSubmit={(event) => { event.preventDefault(); void save(); }}>
        <SettingsDisclosure boxed className="reach-explainer" summary={t("devices.localNetworks.whoCanReach")}>
          <p className="settings-note">{t("devices.localNetworks.reach", { name: device.name })}</p>
        </SettingsDisclosure>
        <Field label={t("devices.localNetworks.label")} hint={t("devices.localNetworks.hint")}
          error={!invalid.length ? undefined : fix ? t("devices.localNetworks.hostBits", { network: fix.entry, canonical: fix.network })
            : t("devices.localNetworks.invalid", { networks: invalid.join(", ") })}>
          <textarea value={draft} onChange={(event) => setDraft(event.target.value)} placeholder="192.168.1.0/24" rows={3} disabled={busy} spellCheck={false} />
        </Field>
        <div className="command-note">
          <p>{t("devices.localNetworks.linux", { name: device.name })}</p>
          <div className="command-block">
            <code>{FORWARDING_COMMAND}</code>
            <CopyButton value={FORWARDING_COMMAND} label={t("devices.localNetworks.copyCommand")} />
          </div>
          <p>{t("devices.localNetworks.router")}</p>
        </div>
        <p className="settings-note">{t("devices.localNetworks.apply")}</p>
        {error && <InlineError message={error} />}
      </form>
    </DialogContent></Dialog.Portal>
  </Dialog.Root>;
}
