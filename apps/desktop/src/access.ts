import { t, type MessageKey } from "./i18n";
import type {
  ActiveInvitationSummary,
  MemberSummary,
  ServerProfile,
  ServerStatus,
} from "./types";

export type AccessLevel = "owner" | "admin" | "member";

export function resolveAccess(
  profile: Pick<ServerProfile, "role" | "administrator">,
  status: Pick<ServerStatus, "caller_role" | "caller_administrator"> | null,
  connected: boolean,
): { level: AccessLevel; canManage: boolean } {
  const role = status?.caller_role ?? profile.role;
  const administrator = status?.caller_role
    ? Boolean(status.caller_administrator)
    : Boolean(profile.administrator);
  const level = role === "owner" ? "owner" : administrator ? "admin" : "member";
  return {
    level,
    canManage: role === "owner" || (connected && status?.caller_administrator === true),
  };
}

export function memberAccessLevel(
  member: Pick<MemberSummary, "role" | "administrator">,
): AccessLevel {
  if (member.role === "owner") return "owner";
  return member.administrator ? "admin" : "member";
}

const ACCESS_LEVEL_KEYS = {
  owner: "common.role.owner",
  admin: "common.role.admin",
  member: "common.role.member",
} as const satisfies Record<AccessLevel, MessageKey>;

export function accessLevelLabel(level: AccessLevel): string {
  return t(ACCESS_LEVEL_KEYS[level]);
}

export function memberAccessLabel(
  member: Pick<MemberSummary, "role" | "administrator">,
): string {
  return accessLevelLabel(memberAccessLevel(member));
}

export function canManageMember(
  caller: AccessLevel,
  member: Pick<MemberSummary, "role" | "administrator">,
): boolean {
  return caller === "owner" || (caller === "admin" && member.role === "member" && !member.administrator);
}

/** Mirrors the VPS rule: managers, or a member whose policy allows forwarding to their own devices. */
export function canManagePortForwards(
  caller: AccessLevel,
  member: Pick<MemberSummary, "role" | "administrator" | "policy">,
): boolean {
  return canManageMember(caller, member) || (caller === "member" && Boolean(member.policy?.manage_own_port_forwards));
}

/** Mirrors the VPS rule for the mutual-access switch, which a pair needs on both devices. */
export function canManagePeerCommunication(
  caller: AccessLevel,
  member: Pick<MemberSummary, "role" | "administrator" | "policy">,
): boolean {
  return canManageMember(caller, member) || (caller === "member" && Boolean(member.policy?.manage_own_peer_communication));
}

export function canCancelInvitation(
  caller: AccessLevel,
  invitation: ActiveInvitationSummary,
  members: MemberSummary[],
): boolean {
  if (caller === "owner") return true;
  if (caller === "member") return true; // The VPS returns only this member's issued grants.
  if (invitation.administrator) return false;
  if (!invitation.target_member_id) return true;
  const target = members.find((member) => member.id === invitation.target_member_id);
  return Boolean(target && target.role === "member" && !target.administrator);
}

export function canRotateDeviceKeys(
  connected: boolean,
  recoveryPending: boolean,
  anotherServerActive: boolean,
): boolean {
  return !anotherServerActive && (connected || recoveryPending);
}
