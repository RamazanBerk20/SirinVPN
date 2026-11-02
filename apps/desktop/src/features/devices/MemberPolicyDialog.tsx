import * as Dialog from "@radix-ui/react-dialog";
import { ArrowClockwise, Warning } from "@phosphor-icons/react";
import { useId, useState } from "react";
import { api } from "../../api";
import { DialogContent } from "../../components/DialogContent";
import { notify } from "../../components/Toasts";
import { InlineError } from "../../components/ui";
import { errorMessage } from "../../lib/errors";
import type { MemberSummary } from "../../types";
import { MemberPolicyFields } from "./MemberPolicyFields";
import { policyDraft, policyFromDraft, policyFieldErrors } from "./memberPolicy";
import { t } from "../../i18n";

export function MemberPolicyDialog({ serverId, member, onClose, onSaved }: {
  serverId: string; member: MemberSummary; onClose: () => void; onSaved: () => Promise<void>;
}) {
  const form = useId();
  const [draft, setDraft] = useState(() => policyDraft(member.policy));
  const [busy, setBusy] = useState(false), [error, setError] = useState<string | null>(null);
  const invalid = Object.keys(policyFieldErrors(draft)).length > 0;
  const save = async () => {
    if (invalid || busy) return;
    setBusy(true); setError(null);
    try {
      await api.updateMemberPolicy(serverId, member.id, policyFromDraft(draft));
      notify(t("devices.notice.policySaved", { name: member.name }));
      onClose();
      await onSaved();
    } catch (reason) { setError(errorMessage(reason, t("devices.policy.saveFailed"))); }
    finally { setBusy(false); }
  };
  return <Dialog.Root open onOpenChange={(open) => { if (!open && !busy) onClose(); }}>
    <Dialog.Portal><Dialog.Overlay className="dialog-overlay" /><DialogContent className="dialog-content invitation-dialog"
      heading={<>{t("devices.policy.title", { name: member.name })}</>}
      description={<>{t("devices.policy.description")}</>}
      closeDisabled={busy} closeLabel={t("common.action.close")}
      footer={<div className="dialog-commit">
        <p className="dialog-commit-note"><Warning size={17} weight="fill" /> <span>{t("devices.policy.cancelsInvitations", { name: member.name })}</span></p>
        <button className="primary-button" type="submit" form={form} disabled={busy || invalid} title={invalid ? t("devices.policy.fixFields") : undefined}>
          {busy && <ArrowClockwise className="spin" size={17} />}{busy ? t("common.state.saving") : t("devices.policy.save")}
        </button>
      </div>}>
      <form id={form} className="invite-form policy-form" onSubmit={(event) => { event.preventDefault(); void save(); }}>
        <fieldset className="policy-form-fields" disabled={busy}>
          <MemberPolicyFields draft={draft} onChange={setDraft} />
        </fieldset>
        {error && <InlineError message={error} />}
      </form>
    </DialogContent></Dialog.Portal>
  </Dialog.Root>;
}
