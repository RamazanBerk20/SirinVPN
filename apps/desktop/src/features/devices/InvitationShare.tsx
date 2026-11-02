import { invoke, isAndroid } from "../../platform";
import * as Dialog from "@radix-ui/react-dialog";
import { ArrowsOut, ShareNetwork } from "@phosphor-icons/react";
import { CopyButton } from "../../components/CopyButton";
import { DialogContent } from "../../components/DialogContent";
import type { InvitationResult } from "../../types";
import { InvitationQr } from "./InvitationQr";
import { t } from "../../i18n";

export function InvitationShare({ invitation, onShared }: { invitation: InvitationResult; onShared?: () => void }) {
  if (isAndroid) return <SecretQr source="" kind="invitation" code={invitation.code} onShown={onShared} />;
  const source = `data:image/svg+xml;charset=utf-8,${encodeURIComponent(invitation.qr_svg)}`;

  return (
    <div className="invitation-share-grid">
      <div className="qr-share">
        <SecretQr source={source} kind="invitation" code={invitation.code} onShown={onShared} />
        <small>{t("devices.share.qrNote")}</small>
      </div>
      <div className="code-share">
        <span>{t("devices.share.code")}</span>
        <textarea
          className="secret-code-output mono"
          value={invitation.code}
          readOnly
          aria-label={t("devices.share.codeLabel")}
          onCopy={onShared}
        />
      </div>
    </div>
  );
}

/** Secret codes share contrast, sizing, and an unobstructed enlarged view. */
export function SecretQr({ source, kind, code, onShown }: {
  source: string; kind: "invitation" | "recovery"; code: string;
  /** The code was shown full screen or handed to the Android share screen. */
  onShown?: () => void;
}) {
  const recovery = kind === "recovery";
  // The recovery page keeps its own button hierarchy; on the invitation screen sharing is the main action.
  if (isAndroid) return <button className={recovery ? "secondary-button" : "primary-button secret-share-button"} onClick={() => { onShown?.(); void invoke("android_show_secret", { reference: code }); }}>
    {!recovery && <ShareNetwork size={20} aria-hidden="true" />}{t(recovery ? "devices.share.showRecovery" : "devices.share.showInvitation")}
  </button>;
  return <Dialog.Root onOpenChange={(open) => { if (open) onShown?.(); }}>
    <Dialog.Trigger asChild><button type="button" className="invitation-qr-button" aria-label={t(recovery ? "devices.share.enlargeRecovery" : "devices.share.enlargeInvitation")}>
      <InvitationQr source={source} kind={kind} /><span><ArrowsOut size={18} /> {t("devices.share.enlarge")}</span>
    </button></Dialog.Trigger>
    <Dialog.Portal><Dialog.Overlay className="dialog-overlay invitation-qr-overlay" />
      <DialogContent className="dialog-content invitation-qr-dialog" heading={t(recovery ? "devices.share.scanRecovery" : "devices.share.scanInvitation")} aria-describedby={undefined} closeLabel={t("devices.share.closeQr")}
        footer={<CopyButton value={code} className="secondary-button">{t(recovery ? "devices.share.copyRecovery" : "devices.invite.copyCode")}</CopyButton>}>
        <InvitationQr source={source} kind={kind} enlarged />
      </DialogContent>
    </Dialog.Portal>
  </Dialog.Root>;
}
