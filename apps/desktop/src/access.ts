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

export function memberAccessLabel(
  member: Pick<MemberSummary, "role" | "administrator">,
): "Owner" | "Admin" | "Member" {
  if (member.role === "owner") return "Owner";
  return member.administrator ? "Admin" : "Member";
}

export function canManageMember(
  caller: AccessLevel,
  member: Pick<MemberSummary, "role" | "administrator">,
): boolean {
  return caller === "owner" || (caller === "admin" && member.role === "member" && !member.administrator);
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
