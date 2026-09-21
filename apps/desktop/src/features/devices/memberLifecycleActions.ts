import type { MenuAction } from "../../components/ActionMenu";
import { canManageMember } from "../../access";
import type { MemberSummary } from "../../types";

export type MemberLifecycleProps = {
  memberLifecycleAvailable?: boolean | null;
  memberBusy?: string | null;
  onMemberSuspension?: (member: MemberSummary) => Promise<void>;
  onRevokeMemberDevices?: (member: MemberSummary) => Promise<void>;
};

export function memberLifecycleActions(
  member: MemberSummary,
  props: MemberLifecycleProps & { accessLevel: "owner" | "admin" | "member" },
): MenuAction[] {
  if (
    !props.memberLifecycleAvailable ||
    member.role === "owner" ||
    !canManageMember(props.accessLevel, member)
  )
    return [];
  return [
    {
      group: "Member",
      label: member.suspended ? "Reactivate member" : "Suspend member",
      danger: !member.suspended,
      disabled: props.memberBusy != null || !props.onMemberSuspension,
      run: () => void props.onMemberSuspension?.(member),
    },
    {
      group: "Member",
      label: "Revoke all member devices",
      danger: true,
      disabled: props.memberBusy != null || !props.onRevokeMemberDevices,
      run: () => void props.onRevokeMemberDevices?.(member),
    },
  ];
}
