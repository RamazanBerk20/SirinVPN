import { ArrowClockwise, DeviceMobileCamera, UserPlus } from "@phosphor-icons/react";
import { useId, useState } from "react";
import { accessLevelLabel, canCancelInvitation } from "../../access";
import { InlineError } from "../../components/ui";
import { t } from "../../i18n";
import { formatExpiry } from "../../lib/errors";
import type { ActiveInvitationSummary, MemberSummary, MembershipSnapshot } from "../../types";

/** A device code is named after the member it adds to; a new member's code after its recipient. */
export function invitationTitle(invitation: ActiveInvitationSummary, members: MemberSummary[]) {
  if (invitation.target_member_id) {
    const member = members.find((entry) => entry.id === invitation.target_member_id);
    return t("devices.invitations.newDevice", { name: member?.name ?? invitation.member_name });
  }
  return invitation.recipient_names ? t("devices.invitations.newMember") : invitation.member_name;
}

function invitationDetail(invitation: ActiveInvitationSummary, members: MemberSummary[]) {
  const member = invitation.target_member_id ? members.find((entry) => entry.id === invitation.target_member_id) : undefined;
  const role = member?.role === "owner" ? "owner" : (member?.administrator ?? invitation.administrator) ? "admin" : "member";
  const uses = (invitation.max_uses ?? 1) <= 1
    ? t("devices.invitations.singleUse")
    : invitation.uses_remaining === undefined
      ? t("devices.invitations.reusable", { max: invitation.max_uses ?? 1 })
      : t("devices.invitations.usesLeft", { left: invitation.uses_remaining, max: invitation.max_uses ?? 1 });
  return t("devices.invitations.row", { role: accessLevelLabel(role), uses, date: formatExpiry(invitation.expires_at_unix) });
}

export function ActiveInvitations({
  snapshot,
  accessLevel,
  onCancel,
}: {
  snapshot: MembershipSnapshot;
  accessLevel: "owner" | "admin" | "member";
  /** Rejects with the message to show under the invitation. */
  onCancel: (id: string) => Promise<void>;
}) {
  const heading = useId();
  const [busy, setBusy] = useState<string | null>(null);
  const [failure, setFailure] = useState<{ id: string; message: string } | null>(null);
  if (snapshot.active_invitations.length === 0) return null;
  const cancel = async (id: string) => {
    setBusy(id); setFailure(null);
    try { await onCancel(id); }
    catch (reason) { setFailure({ id, message: reason instanceof Error ? reason.message : String(reason) }); }
    finally { setBusy(null); }
  };
  return (
    <section className="invitations-section" aria-labelledby={heading}>
      <h3 id={heading}>
        {t("devices.invitations.title")}
        <span className="count-chip">{snapshot.active_invitations.length}</span>
      </h3>
      <ul className="invitation-items">
        {snapshot.active_invitations.map((invitation) => {
          const Icon = invitation.target_member_id ? DeviceMobileCamera : UserPlus;
          return (
            <li className="invitation-item" key={invitation.id}>
              <div className="invitation-item-main">
                <span className="invitation-item-icon" aria-hidden="true"><Icon size={19} /></span>
                <span className="invitation-item-copy">
                  <strong>{invitationTitle(invitation, snapshot.members)}</strong>
                  <small>{invitationDetail(invitation, snapshot.members)}</small>
                </span>
                {canCancelInvitation(accessLevel, invitation, snapshot.members) && (
                  <button className="text-button danger-text" disabled={busy !== null} onClick={() => void cancel(invitation.id)}>
                    {busy === invitation.id && <ArrowClockwise className="spin" size={15} />}
                    {busy === invitation.id ? t("devices.invitations.cancelling") : t("devices.invitations.cancel")}
                  </button>
                )}
              </div>
              {failure?.id === invitation.id && <InlineError message={failure.message} onRetry={() => void cancel(invitation.id)} retryDisabled={busy !== null} />}
            </li>
          );
        })}
      </ul>
    </section>
  );
}
