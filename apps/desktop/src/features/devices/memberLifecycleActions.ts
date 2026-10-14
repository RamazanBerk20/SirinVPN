import type { MenuAction } from "../../components/ActionMenu";
import { canManageMember } from "../../access";
import { t } from "../../i18n";
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
      group: t("devices.menu.group.member"),
      label: t(member.suspended ? "devices.menu.reactivate" : "devices.menu.suspend"),
      danger: !member.suspended,
      disabled: props.memberBusy != null || !props.onMemberSuspension,
      run: () => void props.onMemberSuspension?.(member),
    },
    {
      group: t("devices.menu.group.member"),
      label: t("devices.menu.revokeAll"),
      danger: true,
      disabled: props.memberBusy != null || !props.onRevokeMemberDevices,
      run: () => void props.onRevokeMemberDevices?.(member),
    },
  ];
}
