import { CaretDown, Key } from "@phosphor-icons/react";
import { canCancelInvitation } from "../../access";
import { formatExpiry } from "../../lib/errors";
import type { MembershipSnapshot } from "../../types";

export function ActiveInvitations({
  snapshot,
  accessLevel,
  onCancel,
}: {
  snapshot: MembershipSnapshot;
  accessLevel: "owner" | "admin" | "member";
  onCancel: (id: string) => Promise<void>;
}) {
  if (snapshot.active_invitations.length === 0)
    return (
      <p className="invitation-empty">
        No active invitations. Invite someone to give them access.
      </p>
    );
  return (
    <details className="access-disclosure invitations-disclosure">
      <summary>
        <Key size={17} />
        <span>Active invitations</span>
        <span className="disclosure-count">
          {snapshot.active_invitations.length}
        </span>
        <CaretDown size={16} className="disclosure-chevron" />
      </summary>
      <div className="invitation-list">
        {snapshot.active_invitations.map((invitation) => {
          const member = invitation.target_member_id
            ? snapshot.members.find((member) => member.id === invitation.target_member_id)
            : undefined;
          const role = member?.role === "owner"
            ? "Owner"
            : (member?.administrator ?? invitation.administrator) ? "Admin" : "Member";
          return (
            <div className="invitation-row" key={invitation.id}>
              <span>
                <strong>{invitation.recipient_names && !invitation.target_member_id ? "New member invitation" : invitation.member_name}</strong>
                <small>
                  {role} · expires at {formatExpiry(invitation.expires_at_unix)}
                </small>
              </span>
              {canCancelInvitation(
                accessLevel,
                invitation,
                snapshot.members,
              ) && (
                <button
                  className="text-button danger-text"
                  onClick={() => void onCancel(invitation.id)}
                >
                  Cancel
                </button>
              )}
            </div>
          );
        })}
      </div>
    </details>
  );
}
