import * as Dialog from "@radix-ui/react-dialog";
import { ArrowClockwise } from "@phosphor-icons/react";
import { useId, useRef, useState } from "react";
import { DialogContent } from "../../components/DialogContent";
import { Field, InlineError } from "../../components/ui";
import { t } from "../../i18n";

export const MAX_DEVICE_NAME = 64;

/** Why a device name can't be saved, or null. The server applies the same limits. */
export function deviceNameProblem(name: string): string | null {
  const trimmed = name.trim();
  if (!trimmed) return t("devices.rename.empty");
  if ([...trimmed].length > MAX_DEVICE_NAME) return t("devices.rename.tooLong", { count: MAX_DEVICE_NAME });
  if (/[\u0000-\u001f\u007f-\u009f]/.test(trimmed)) return t("devices.rename.invalid");
  return null;
}

export function RenameDeviceDialog({ device, onRename, onClose }: {
  device: { id: string; name: string };
  /** Rejects with the message to show when the server refuses. */
  onRename: (deviceId: string, name: string) => Promise<void>;
  onClose: () => void;
}) {
  const form = useId();
  const input = useRef<HTMLInputElement>(null);
  const [name, setName] = useState(device.name);
  const [busy, setBusy] = useState(false), [error, setError] = useState<string | null>(null);
  const problem = deviceNameProblem(name);
  const unchanged = name.trim() === device.name;
  const save = async () => {
    if (problem || unchanged || busy) return;
    setBusy(true); setError(null);
    try {
      await onRename(device.id, name.trim());
      onClose();
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : String(reason));
    } finally { setBusy(false); }
  };
  return <Dialog.Root open onOpenChange={(open) => { if (!open && !busy) onClose(); }}>
    <Dialog.Portal><Dialog.Overlay className="dialog-overlay" />
      <DialogContent className="dialog-content rename-dialog"
        heading={<>{t("devices.rename.title", { name: device.name })}</>}
        description={<>{t("devices.rename.description")}</>}
        closeDisabled={busy} closeLabel={t("common.action.close")}
        onOpenAutoFocus={(event) => { event.preventDefault(); input.current?.focus(); input.current?.select(); }}
        footer={<div className="dialog-commit">
          <button type="button" className="secondary-button" disabled={busy} onClick={onClose}>{t("common.action.cancel")}</button>
          <button type="submit" form={form} className="primary-button" disabled={busy || Boolean(problem) || unchanged}>
            {busy && <ArrowClockwise className="spin" size={17} />}{busy ? t("common.state.saving") : t("devices.rename.save")}
          </button>
        </div>}>
        <form id={form} className="invite-form" onSubmit={(event) => { event.preventDefault(); void save(); }}>
          <Field label={t("devices.rename.label")} error={problem ?? undefined} hint={t("devices.rename.hint")}>
            <input ref={input} value={name} maxLength={MAX_DEVICE_NAME * 2} autoComplete="off" disabled={busy}
              onChange={(event) => { setName(event.target.value); setError(null); }} />
          </Field>
          {error && <InlineError message={error} />}
        </form>
      </DialogContent>
    </Dialog.Portal>
  </Dialog.Root>;
}
