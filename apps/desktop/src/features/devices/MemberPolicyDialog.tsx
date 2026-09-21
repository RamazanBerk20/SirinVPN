import * as Dialog from "@radix-ui/react-dialog";
import { useState } from "react";
import { api } from "../../api";
import { DialogContent } from "../../components/DialogContent";
import { InlineError } from "../../components/ui";
import { errorMessage } from "../../lib/errors";
import type { MemberSummary } from "../../types";
import { MemberPolicyFields } from "./MemberPolicyFields";
import { policyDraft, policyFromDraft, policyFieldErrors } from "./memberPolicy";

export function MemberPolicyDialog({ serverId, member, onClose, onSaved }: {
  serverId: string; member: MemberSummary; onClose: () => void; onSaved: () => Promise<void>;
}) {
  const [draft, setDraft] = useState(() => policyDraft(member.policy));
  const [busy, setBusy] = useState(false), [error, setError] = useState<string | null>(null);
  const save = async () => {
    if (Object.keys(policyFieldErrors(draft)).length) {
      setError("Correct the highlighted access policy fields before saving.");
      document.querySelector<HTMLElement>('[aria-invalid="true"]')?.focus();
      return;
    }
    setBusy(true); setError(null);
    try {
      await api.updateMemberPolicy(serverId, member.id, policyFromDraft(draft));
      await onSaved(); onClose();
    } catch (reason) { setError(errorMessage(reason, "The access policy could not be saved.")); }
    finally { setBusy(false); }
  };
  return <Dialog.Root open onOpenChange={(open) => { if (!open && !busy) onClose(); }}>
    <Dialog.Portal><Dialog.Overlay className="dialog-overlay" /><DialogContent className="dialog-content invitation-dialog"
          heading={<>Access policy for {member.name}</>}
          description={<>These rules apply to every device in this membership. Saving cancels pending invitations for this member and invitations they issued.</>}
          closeDisabled={busy} closeLabel="Close">
      <form className="invite-form" onSubmit={(event) => { event.preventDefault(); void save(); }}>
        <MemberPolicyFields draft={draft} onChange={setDraft} />
        {error && <InlineError message={error} />}
        <button className="primary-button" type="submit" disabled={busy}>{busy ? "Saving" : "Save access policy"}</button>
      </form>
    </DialogContent></Dialog.Portal>
  </Dialog.Root>;
}
