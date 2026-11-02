import type { MenuAction } from "../../components/ActionMenu";
import { canManageMember } from "../../access";
import { t } from "../../i18n";
import type { MemberSummary, MembershipSnapshot } from "../../types";

export type MemberLifecycleProps = {
  memberLifecycleAvailable?: boolean | null;
  memberBusy?: string | null;
  onMemberSuspension?: (member: MemberSummary) => Promise<void>;
  onRevokeMemberDevices?: (member: MemberSummary) => Promise<void>;
};

export type MemberActionProps = MemberLifecycleProps & {
  snapshot: MembershipSnapshot;
  accessLevel: "owner" | "admin" | "member";
  accessBusy: string | null;
  onPolicy?: (member: MemberSummary) => void;
  onWireGuard?: (member: MemberSummary) => void;
  onInvite: (member: MemberSummary) => void;
  onAccess: (member: MemberSummary) => Promise<void>;
  onTransfer: (member: MemberSummary) => Promise<void>;
};

/** Only these devices can manage the server, so only they keep or receive ownership. */
export const managedDevices = (member: MemberSummary) => member.devices.filter((device) => !device.wireguard_only);

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

/** Whether the caller may add a device to this member, and why it is blocked right now. */
export function addDeviceState(member: MemberSummary, props: Pick<MemberActionProps, "accessLevel" | "memberBusy">) {
  const allowed = canManageMember(props.accessLevel, member) || (props.accessLevel === "member" && Boolean(member.policy?.add_own_devices));
  const limit = member.policy?.device_limit;
  const reason = member.suspended
    ? t("devices.menu.reactivateFirst")
    : limit && member.devices.length >= limit
      ? t("devices.menu.limitReached", { count: limit })
      : undefined;
  return { allowed, disabled: Boolean(reason) || props.memberBusy != null, reason };
}

/** Everything that changes the member as a whole, so it never hides behind one device's menu. */
export function memberActions(member: MemberSummary, props: MemberActionProps, includeAddDevice: boolean): MenuAction[] {
  const group = t("devices.menu.group.member");
  const manageable = canManageMember(props.accessLevel, member);
  const hasInvitation = props.snapshot.active_invitations.some((invitation) => invitation.target_member_id === member.id);
  const actions: MenuAction[] = [];
  const add = addDeviceState(member, props);
  if (includeAddDevice && add.allowed)
    actions.push({ group, label: t("devices.menu.addDeviceFor", { name: member.name }), disabled: add.disabled, reason: add.reason, run: () => props.onInvite(member) });
  if (props.onWireGuard && manageable)
    actions.push({ group, label: t("devices.menu.addWireguardFor", { name: member.name }), disabled: member.suspended || props.memberBusy != null,
      reason: member.suspended ? t("devices.menu.reactivateFirst") : undefined, run: () => props.onWireGuard?.(member) });
  if (props.onPolicy && member.role !== "owner" && manageable)
    actions.push({ group, label: t("devices.menu.accessPolicy"), run: () => props.onPolicy?.(member) });
  if (props.accessLevel === "owner" && member.role === "member")
    actions.push({
      group,
      label: t(member.administrator ? "devices.menu.removeAdmin" : "devices.menu.makeAdmin"),
      disabled: props.accessBusy === member.id || hasInvitation || props.memberBusy != null,
      reason: hasInvitation ? t("devices.menu.cancelInvitationFirst") : undefined,
      run: () => void props.onAccess(member),
    });
  actions.push(...memberLifecycleActions(member, props));
  if (props.accessLevel === "owner" && member.role === "member") {
    const noDevice = managedDevices(member).length === 0;
    actions.push({
      group: t("devices.menu.group.ownership"),
      label: t("devices.menu.transfer"),
      danger: true,
      disabled: props.accessBusy === member.id || hasInvitation || member.suspended || props.memberBusy != null || noDevice,
      reason: member.suspended
        ? t("devices.menu.reactivateFirst")
        : hasInvitation
          ? t("devices.menu.cancelInvitationFirst")
          : noDevice ? t("devices.menu.needsManagedDevice") : undefined,
      run: () => void props.onTransfer(member),
    });
  }
  return actions;
}
