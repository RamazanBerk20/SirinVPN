import { invoke, isAndroid } from "../../platform";
import { copyText } from "../../lib/clipboard";
import * as Dialog from "@radix-ui/react-dialog";
import { ArrowsOut } from "@phosphor-icons/react";
import { DialogContent } from "../../components/DialogContent";
import type { InvitationResult } from "../../types";
import { InvitationQr } from "./InvitationQr";
import { t } from "../../i18n";

export function InvitationShare({ invitation }: { invitation: InvitationResult }) {
  if (isAndroid) return <button className="secondary-button" onClick={() => void invoke("android_show_secret", { reference: invitation.code })}>{t("devices.share.showInvitation")}</button>;
  const source = `data:image/svg+xml;charset=utf-8,${encodeURIComponent(invitation.qr_svg)}`;

  return (
    <div className="invitation-share-grid">
      <div className="qr-share">
        <SecretQr source={source} kind="invitation" code={invitation.code} />
        <small>{t("devices.share.qrNote")}</small>
      </div>
      <div className="code-share">
        <span>{t("devices.share.code")}</span>
        <textarea
          className="secret-code-output mono"
          value={invitation.code}
          readOnly
          aria-label={t("devices.share.codeLabel")}
        />
      </div>
    </div>
  );
}

/** Secret codes share contrast, sizing, and an unobstructed enlarged view. */
export function SecretQr({ source, kind, code }: { source: string; kind: "invitation" | "recovery"; code: string }) {
  const recovery = kind === "recovery";
  if (isAndroid) return <button className="secondary-button" onClick={() => void invoke("android_show_secret", { reference: code })}>{t(recovery ? "devices.share.showRecovery" : "devices.share.showInvitation")}</button>;
  return <Dialog.Root>
    <Dialog.Trigger asChild><button type="button" className="invitation-qr-button" aria-label={t(recovery ? "devices.share.enlargeRecovery" : "devices.share.enlargeInvitation")}>
      <InvitationQr source={source} kind={kind} /><span><ArrowsOut size={18} /> {t("devices.share.enlarge")}</span>
    </button></Dialog.Trigger>
    <Dialog.Portal><Dialog.Overlay className="dialog-overlay invitation-qr-overlay" />
      <DialogContent className="dialog-content invitation-qr-dialog" heading={t(recovery ? "devices.share.scanRecovery" : "devices.share.scanInvitation")} aria-describedby={undefined} closeLabel={t("devices.share.closeQr")}
        footer={<button className="secondary-button" onClick={() => void copyText(code).catch(() => {})}>{t(recovery ? "devices.share.copyRecovery" : "devices.share.copyInvitation")}</button>}>
        <InvitationQr source={source} kind={kind} enlarged />
      </DialogContent>
    </Dialog.Portal>
  </Dialog.Root>;
}
