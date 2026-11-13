import { t, type MessageKey } from "./i18n";
import type {
  ActiveInvitationSummary,
  MemberPolicy,
  MemberSummary,
  ServerProfile,
  ServerStatus,
} from "./types";

/** A person's role: Owner (exactly one), Admin or Member. On the wire an Admin is a Member with `administrator`. */
export type Role = "owner" | "admin" | "member";
/** The caller's own role. Kept as a separate name for the workspace, which calls it the access level. */
export type AccessLevel = Role;

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

export function personRole(person: Pick<MemberSummary, "role" | "administrator">): Role {
  if (person.role === "owner") return "owner";
  return person.administrator ? "admin" : "member";
}

const ROLE_KEYS = {
  owner: "common.role.owner",
  admin: "common.role.admin",
  member: "common.role.member",
} as const satisfies Record<Role, MessageKey>;

/** The one fixed sentence that says what a role may do, shown wherever a role is chosen or described. */
const ROLE_DESCRIPTION_KEYS = {
  owner: "devices.role.description.owner",
  admin: "devices.role.description.admin",
  member: "devices.role.description.member",
} as const satisfies Record<Role, MessageKey>;

export const roleLabel = (role: Role) => t(ROLE_KEYS[role]);
export const roleDescription = (role: Role) => t(ROLE_DESCRIPTION_KEYS[role]);

/** Mirrors the VPS rule (`can_manage_member`): the Owner manages everyone, an Admin manages Members. */
export function canManagePerson(viewer: Role, person: Pick<MemberSummary, "role" | "administrator">): boolean {
  return viewer === "owner" || (viewer === "admin" && personRole(person) === "member");
}

type OwnPermission = keyof Pick<MemberPolicy, "add_own_devices" | "manage_own_peer_communication" | "manage_own_port_forwards">;

/**
 * Mirrors the VPS rule for a person's own devices: a manager, or the person themselves when their
 * permissions allow it. This includes an Admin acting on their own devices, which the Owner grants.
 */
export function canActOnOwn(
  viewer: Role,
  person: Pick<MemberSummary, "id" | "role" | "administrator" | "policy">,
  selfId: string | undefined,
  permission: OwnPermission,
): boolean {
  return canManagePerson(viewer, person) || (person.id === selfId && Boolean(person.policy?.[permission]));
}

/**
 * Mirrors the VPS rule (`can_add_device_to`). An Admin may always add their own devices only on servers
 * with `admin_own_devices_enabled`; older servers need the Owner's `add_own_devices` grant.
 */
export function canAddDeviceFor(
  viewer: Role,
  person: Pick<MemberSummary, "id" | "role" | "administrator" | "policy">,
  selfId: string | undefined,
  adminOwnDevices: boolean,
): boolean {
  return canActOnOwn(viewer, person, selfId, "add_own_devices") || (person.id === selfId && viewer === "admin" && adminOwnDevices);
}

/** Mirrors the VPS rule: managers of the code's person, and whoever created the code. */
export function canCancelJoinCode(
  viewer: Role,
  code: ActiveInvitationSummary,
  people: MemberSummary[],
  selfId: string | undefined,
): boolean {
  if (viewer === "owner") return true;
  if (viewer === "member") return true; // The VPS returns only the codes this person created.
  if (code.target_member_id && code.target_member_id === selfId) return true;
  if (code.administrator) return false;
  if (!code.target_member_id) return true;
  const target = people.find((person) => person.id === code.target_member_id);
  return Boolean(target && personRole(target) === "member");
}

export function canRotateDeviceKeys(
  connected: boolean,
  recoveryPending: boolean,
  anotherServerActive: boolean,
): boolean {
  return !anotherServerActive && (connected || recoveryPending);
}
