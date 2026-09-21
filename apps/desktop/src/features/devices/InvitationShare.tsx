import { invoke, isAndroid } from "../../platform";
import { copyText } from "../../lib/clipboard";
import * as Dialog from "@radix-ui/react-dialog";
import { ArrowsOut } from "@phosphor-icons/react";
import { DialogContent } from "../../components/DialogContent";
import type { InvitationResult } from "../../types";
import { InvitationQr } from "./InvitationQr";

export function InvitationShare({ invitation }: { invitation: InvitationResult }) {
  if (isAndroid) return <button className="secondary-button" onClick={() => void invoke("android_show_secret", { reference: invitation.code })}>View or share invitation securely</button>;
  const source = `data:image/svg+xml;charset=utf-8,${encodeURIComponent(invitation.qr_svg)}`;

  return (
    <div className="invitation-share-grid">
      <div className="qr-share">
        <SecretQr source={source} kind="invitation" code={invitation.code} />
        <small>Contains the same invitation secret as the long code.</small>
      </div>
      <div className="code-share">
        <span>Long code</span>
        <textarea
          className="secret-code-output mono"
          value={invitation.code}
          readOnly
          aria-label="Invitation code"
        />
      </div>
    </div>
  );
}

/** Secret codes share contrast, sizing, and an unobstructed enlarged view. */
export function SecretQr({ source, kind, code }: { source: string; kind: "invitation" | "recovery"; code: string }) {
  if (isAndroid) return <button className="secondary-button" onClick={() => void invoke("android_show_secret", { reference: code })}>View or share {kind} securely</button>;
  return <Dialog.Root>
    <Dialog.Trigger asChild><button type="button" className="invitation-qr-button" aria-label={`Enlarge ${kind} QR code`}>
      <InvitationQr source={source} kind={kind} /><span><ArrowsOut size={18} /> Enlarge QR code</span>
    </button></Dialog.Trigger>
    <Dialog.Portal><Dialog.Overlay className="dialog-overlay invitation-qr-overlay" />
      <DialogContent className="dialog-content invitation-qr-dialog" heading={`Scan ${kind} QR`} aria-describedby={undefined} closeLabel="Close enlarged QR code"
        footer={<button className="secondary-button" onClick={() => void copyText(code).catch(() => {})}>Copy {kind} code</button>}>
        <InvitationQr source={source} kind={kind} enlarged />
      </DialogContent>
    </Dialog.Portal>
  </Dialog.Root>;
}
