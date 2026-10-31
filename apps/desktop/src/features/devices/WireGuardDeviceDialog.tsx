import * as Dialog from "@radix-ui/react-dialog";
import { ArrowClockwise, Key, Warning } from "@phosphor-icons/react";
import { useState } from "react";
import { api } from "../../api";
import { DialogContent } from "../../components/DialogContent";
import { Field, InlineError } from "../../components/ui";
import { preferredBackupPath } from "../../lib/backupPaths";
import { errorMessage } from "../../lib/errors";
import { save } from "../../lib/nativeDialog";
import type { MemberPolicy, MemberSummary, WireGuardDeviceResult } from "../../types";
import { InvitationQr } from "./InvitationQr";
import { t } from "../../i18n";

/** Matches the native file name rule: wg-quick takes the tunnel name from it. */
export function wireguardFileName(deviceName: string) {
  const name = deviceName.trim().replace(/[^a-zA-Z0-9_=+.-]/g, "-").replace(/^[-.]+|[-.]+$/g, "").slice(0, 15);
  return `${name || "sirinvpn"}.conf`;
}

export function WireGuardDeviceDialog({ serverId, target, delegatedPolicy, onClose, onCreated }: {
  serverId: string;
  target: MemberSummary | null;
  /** A delegated Member grants at most its own policy to a new member. */
  delegatedPolicy?: MemberPolicy;
  onClose: () => void;
  onCreated: () => Promise<void>;
}) {
  const [memberName, setMemberName] = useState("");
  const [deviceName, setDeviceName] = useState("");
  const [path, setPath] = useState("");
  const [created, setCreated] = useState<WireGuardDeviceResult | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const ready = Boolean(deviceName.trim() && (target || memberName.trim()));

  const chooseFile = async () => {
    try {
      const selected = await save({
        title: t("devices.wireguard.file"),
        defaultPath: await preferredBackupPath(wireguardFileName(deviceName)),
        filters: [{ name: t("devices.wireguard.fileType"), extensions: ["conf"] }],
      });
      if (typeof selected === "string") setPath(selected);
    } catch (reason) {
      setError(errorMessage(reason, t("devices.wireguard.pickerFailed")));
    }
  };

  const create = async () => {
    if (busy || !ready) return;
    setBusy(true);
    setError(null);
    try {
      setCreated(await api.createWireGuardDevice(
        serverId,
        target?.name ?? memberName.trim(),
        deviceName.trim(),
        target?.id ?? null,
        target || !delegatedPolicy ? undefined : { ...delegatedPolicy, invite_members: false },
        path || null,
      ));
      await onCreated();
    } catch (reason) {
      setError(errorMessage(reason, t("devices.wireguard.failed")));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Dialog.Root open onOpenChange={(open) => { if (!open && !busy) onClose(); }}>
      <Dialog.Portal>
        <Dialog.Overlay className="dialog-overlay" />
        <DialogContent className={`dialog-content invitation-dialog${created ? " invitation-dialog-ready" : ""}`}
          heading={<>{created
            ? t("devices.wireguard.titleReady")
            : target ? t("devices.wireguard.titleForMember", { name: target.name }) : t("devices.wireguard.title")}</>}
          description={<>{created ? t("devices.wireguard.descriptionReady") : t("devices.wireguard.description")}</>}
          closeDisabled={busy} closeLabel={t("common.action.close")}>
          {created ? (
            <div className="invitation-result">
              <div className="warning-note">
                <Warning size={18} weight="fill" />
                <span>{t("devices.wireguard.secretWarning")}</span>
              </div>
              <div className="qr-share">
                <InvitationQr source={`data:image/svg+xml;charset=utf-8,${encodeURIComponent(created.qr_svg)}`} kind="wireguard" />
                {path && <small className="mono">{t("devices.wireguard.saved", { path })}</small>}
              </div>
              <p className="settings-note">{t("devices.wireguard.revokeHint")}</p>
            </div>
          ) : (
            <form className="invite-form" onSubmit={(event) => { event.preventDefault(); void create(); }}>
              {!target && <Field label={t("devices.wireguard.memberName")}>
                <input value={memberName} maxLength={64} required autoComplete="off" onChange={(event) => setMemberName(event.target.value)} />
              </Field>}
              <Field label={t("devices.wireguard.deviceName")}>
                <input value={deviceName} maxLength={64} required autoComplete="off" onChange={(event) => setDeviceName(event.target.value)} />
              </Field>
              <Field label={t("devices.wireguard.file")} hint={t("devices.wireguard.fileHint")}>
                <div className="file-picker-row">
                  <input className="mono" value={path} readOnly placeholder={t("devices.wireguard.noFile")} />
                  <button className="secondary-button" type="button" onClick={() => void chooseFile()} disabled={busy}>
                    {t("devices.wireguard.chooseFile")}
                  </button>
                </div>
              </Field>
              {error && <InlineError message={error} />}
              <button className="primary-button" type="submit" disabled={busy || !ready}>
                {busy ? <ArrowClockwise className="spin" size={18} /> : <Key size={18} />}
                {busy ? t("devices.wireguard.creating") : t("devices.wireguard.create")}
              </button>
            </form>
          )}
        </DialogContent>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
