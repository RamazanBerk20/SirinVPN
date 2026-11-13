import { canActOnOwn, canAddDeviceFor, canCancelJoinCode, canManagePerson, personRole, type Role } from "../../access";
import { t } from "../../i18n";
import type {
  ActiveInvitationSummary,
  CurrentConfiguration,
  DeviceSummary,
  MemberSummary,
  MembershipSnapshot,
} from "../../types";

/* ---------- What the server can do ---------- */

export interface Capabilities {
  /** Suspend, resume and remove a person. */
  lifecycle: boolean;
  /** Limits and permissions, and codes that several devices or people can use. */
  policies: boolean;
  /** The joiner names the device (and, for a new person, themselves) when joining. */
  recipientNames: boolean;
  /** A new person's code carries the name the inviter typed. */
  namedCodes: boolean;
  renamePerson: boolean;
  adminOwnDevices: boolean;
  /** Only where the platform can export a WireGuard configuration. */
  wireguard: boolean;
  subnetRoutes: boolean;
  devicePairs: boolean;
  portForwards: boolean;
}

export function capabilities(configuration: CurrentConfiguration, android: boolean): Capabilities {
  return {
    lifecycle: Boolean(configuration.member_lifecycle_enabled),
    policies: Boolean(configuration.reusable_invitations_enabled),
    recipientNames: Boolean(configuration.recipient_names_enabled),
    namedCodes: Boolean(configuration.named_join_codes_enabled),
    renamePerson: Boolean(configuration.person_rename_enabled),
    adminOwnDevices: Boolean(configuration.admin_own_devices_enabled),
    // The Android runtime has no command for exporting WireGuard configurations yet.
    wireguard: Boolean(configuration.wireguard_devices_enabled) && !android,
    subnetRoutes: Boolean(configuration.subnet_routes_enabled),
    devicePairs: Boolean(configuration.device_pairs_enabled),
    portForwards: Boolean(configuration.port_forwarding_enabled),
  };
}

/** Servers from before people management answer the membership read but offer none of its actions. */
export const supportsPeople = (configuration: CurrentConfiguration) =>
  Boolean(configuration.member_lifecycle_enabled || configuration.recipient_names_enabled);

/* ---------- The page ---------- */

export interface Saved { snapshot: MembershipSnapshot; at: number }

export type PageState =
  | { kind: "disconnected"; saved: Saved | null }
  | { kind: "loading" }
  | { kind: "ready"; snapshot: MembershipSnapshot; caps: Capabilities; at: number; refreshing: boolean }
  /** The last list, read-only, while the server can't be read. */
  | { kind: "stale"; snapshot: MembershipSnapshot; at: number; error: string; refreshing: boolean }
  | { kind: "failed"; error: string; refreshing: boolean }
  | { kind: "unsupported"; snapshot: MembershipSnapshot | null };

export type PageEvent =
  | { type: "disconnected"; saved: Saved | null }
  | { type: "refreshing" }
  | { type: "loaded"; snapshot: MembershipSnapshot; configuration: CurrentConfiguration; android: boolean; at: number }
  | { type: "changed"; snapshot: MembershipSnapshot; at: number }
  | { type: "failed"; error: string; configuration?: CurrentConfiguration; snapshot?: MembershipSnapshot; at: number };

export function pageReducer(state: PageState, event: PageEvent): PageState {
  switch (event.type) {
    case "disconnected":
      return { kind: "disconnected", saved: event.saved && { ...event.saved, snapshot: withoutActivity(event.saved.snapshot) } };
    case "refreshing":
      if (state.kind === "ready" || state.kind === "stale" || state.kind === "failed") return { ...state, refreshing: true };
      return state.kind === "unsupported" ? state : { kind: "loading" };
    case "loaded":
      if (!supportsPeople(event.configuration)) return { kind: "unsupported", snapshot: event.snapshot };
      return { kind: "ready", snapshot: event.snapshot, caps: capabilities(event.configuration, event.android), at: event.at, refreshing: false };
    case "changed":
      // A mutation's answer is authoritative; outside "ready" there was nothing to change.
      return state.kind === "ready" ? { ...state, snapshot: event.snapshot, at: event.at } : state;
    case "failed": {
      if (event.configuration && !supportsPeople(event.configuration))
        return { kind: "unsupported", snapshot: event.snapshot ?? snapshotOf(state) };
      const snapshot = event.snapshot ?? snapshotOf(state);
      const at = event.snapshot ? event.at : state.kind === "ready" || state.kind === "stale" ? state.at : event.at;
      return snapshot ? { kind: "stale", snapshot: withoutActivity(snapshot), at, error: event.error, refreshing: false }
        : { kind: "failed", error: event.error, refreshing: false };
    }
  }
}

export function snapshotOf(state: PageState): MembershipSnapshot | null {
  switch (state.kind) {
    case "ready": case "stale": return state.snapshot;
    case "disconnected": return state.saved?.snapshot ?? null;
    case "unsupported": return state.snapshot;
    default: return null;
  }
}

/** Activity read earlier says nothing about now. */
export function withoutActivity(snapshot: MembershipSnapshot): MembershipSnapshot {
  return { ...snapshot, members: snapshot.members.map((person) => ({ ...person,
    devices: person.devices.map((device) => ({ ...device, recent_handshake: undefined })),
  })) };
}

/* ---------- The one open panel or dialog ---------- */

export type Whose = { kind: "self" } | { kind: "person"; personId: string } | { kind: "new" };

export type Overlay =
  | null
  | { kind: "person"; personId: string; view: "main" | "makeOwner" }
  | { kind: "device"; deviceId: string }
  | { kind: "add"; preset: Whose | null };

/* ---------- People and devices ---------- */

export interface Viewer {
  role: Role;
  /** The person who owns this device. */
  selfId?: string;
  currentDeviceId?: string;
  caps: Capabilities;
}

export function selfPerson(snapshot: MembershipSnapshot, currentDeviceId: string | undefined): MemberSummary | undefined {
  return snapshot.members.find((person) => person.devices.some((device) => device.id === currentDeviceId));
}

const ROLE_ORDER: Record<Role, number> = { owner: 0, admin: 1, member: 2 };

/** "My devices" first, then everyone else: the Owner, Admins, Members, each in the server's order. */
export function groupPeople(snapshot: MembershipSnapshot, currentDeviceId: string | undefined) {
  const self = selfPerson(snapshot, currentDeviceId) ?? null;
  const others = snapshot.members.filter((person) => person !== self)
    .map((person, index) => ({ person, index }))
    .sort((a, b) => ROLE_ORDER[personRole(a.person)] - ROLE_ORDER[personRole(b.person)] || a.index - b.index)
    .map(({ person }) => person);
  return { self, others };
}

export function findDevice(snapshot: MembershipSnapshot, deviceId: string) {
  for (const person of snapshot.members) {
    const device = person.devices.find((entry) => entry.id === deviceId);
    if (device) return { person, device };
  }
  return null;
}

export type Presence = "suspended" | "active" | "idle" | "unknown";

/** One rule for every device, this one included: what the VPS last saw of it. */
export function presence(person: Pick<MemberSummary, "suspended">, device: Pick<DeviceSummary, "recent_handshake">): Presence {
  if (person.suspended) return "suspended";
  if (device.recent_handshake === true) return "active";
  return device.recent_handshake === false ? "idle" : "unknown";
}

export const PRESENCE_KEYS = {
  suspended: "devices.presence.suspended",
  active: "devices.presence.active",
  idle: "devices.presence.idle",
  unknown: "devices.presence.unknown",
} as const;

export function pairsOf(snapshot: MembershipSnapshot, deviceId: string) {
  return (snapshot.device_pairs ?? []).filter((pair) => pair.device_id === deviceId || pair.peer_device_id === deviceId);
}

export const forwardsOf = (snapshot: MembershipSnapshot, deviceId: string) =>
  (snapshot.port_forwards ?? []).filter((forward) => forward.device_id === deviceId);

/** One plain line about what a device can do, e.g. "SirinVPN app, reaches other devices, shares 192.168.1.0/24". */
export function deviceSummary(snapshot: MembershipSnapshot, device: DeviceSummary): string {
  const parts = [t(device.wireguard_only ? "devices.summary.wireguardApp" : "devices.summary.sirinApp")];
  const pairs = pairsOf(snapshot, device.id).length;
  if (device.peer_communication_enabled) parts.push(t("devices.summary.reachesOthers"));
  else if (pairs > 0) parts.push(t("devices.summary.paired", { count: pairs }));
  else parts.push(t("devices.summary.internetOnly"));
  const routes = device.subnet_routes ?? [];
  if (routes.length === 1) parts.push(t("devices.summary.sharesNetwork", { network: routes[0] }));
  else if (routes.length > 1) parts.push(t("devices.summary.sharesNetworks", { count: routes.length }));
  const forwards = forwardsOf(snapshot, device.id).length;
  if (forwards > 0) parts.push(t("devices.summary.forwards", { count: forwards }));
  return parts.join(" · "); // unit lists have no separator in several locales (tr, ja), which runs the facts together
}

/* ---------- Join codes ---------- */

/** Codes that bring a device for this person, or that this person created (when the server says who). */
export function codesFor(snapshot: MembershipSnapshot, personId: string): ActiveInvitationSummary[] {
  return snapshot.active_invitations.filter((code) => code.target_member_id === personId || code.issued_by_member_id === personId);
}

export function codeTitle(code: ActiveInvitationSummary, people: MemberSummary[]): string {
  if (code.target_member_id) {
    const person = people.find((entry) => entry.id === code.target_member_id);
    return t("devices.codes.forPerson", { name: person?.name ?? code.member_name });
  }
  if ((code.max_uses ?? 1) > 1) return t("devices.codes.severalPeople");
  return code.recipient_names ? t("devices.codes.newPerson") : t("devices.codes.newNamed", { name: code.member_name });
}

/* ---------- Who may do what ---------- */

/** Absent (null), or shown with an optional reason it can't be used right now. */
export type Gate = null | { blocked?: string };
const open: Gate = {};
const blocked = (reason: string): Gate => ({ blocked: reason });

const managedDevices = (person: MemberSummary) => person.devices.filter((device) => !device.wireguard_only);

/** Whether a device can be added for this person now. */
export function addDeviceGate(viewer: Viewer, person: MemberSummary): Gate {
  if (!canAddDeviceFor(viewer.role, person, viewer.selfId, viewer.caps.adminOwnDevices)) return null;
  if (person.suspended) return blocked(t("devices.gate.resumeFirst", { name: person.name }));
  const limit = person.policy?.device_limit;
  if (limit && person.devices.length >= limit) return blocked(t("devices.gate.limitReached", { count: limit }));
  return open;
}

/** Whether the viewer may add a device for someone new, and with which roles. */
export function newPersonRoles(viewer: Viewer, self: MemberSummary | undefined): Role[] {
  if (viewer.role === "owner") return ["member", "admin"];
  if (viewer.role === "admin") return ["member"];
  return self?.policy?.invite_members && viewer.caps.policies ? ["member"] : [];
}

export interface PersonPermissions {
  addDevice: Gate;
  rename: Gate;
  /** Member ↔ Admin. */
  role: Gate;
  makeOwner: Gate;
  limits: Gate;
  suspend: Gate;
  remove: Gate;
}

export function personPermissions(viewer: Viewer, person: MemberSummary): PersonPermissions {
  const role = personRole(person);
  const manage = canManagePerson(viewer.role, person) && role !== "owner";
  const owner = viewer.role === "owner" && role !== "owner";
  const eligible = managedDevices(person);
  return {
    addDevice: addDeviceGate(viewer, person),
    rename: viewer.caps.renamePerson && (canManagePerson(viewer.role, person) || person.id === viewer.selfId) ? open : null,
    role: owner ? open : null,
    makeOwner: !owner ? null
      : person.suspended ? blocked(t("devices.gate.resumeFirst", { name: person.name }))
        : eligible.length === 0 ? blocked(t("devices.gate.needsAppDevice")) : open,
    limits: manage && viewer.caps.policies ? open : null,
    suspend: manage && viewer.caps.lifecycle ? open : null,
    remove: manage && viewer.caps.lifecycle ? open : null,
  };
}

export interface DevicePermissions {
  rename: Gate;
  peer: Gate;
  pairs: Gate;
  localNetworks: Gate;
  portForwards: Gate;
  remove: Gate;
}

export function devicePermissions(viewer: Viewer, person: MemberSummary, device: DeviceSummary): DevicePermissions {
  const manage = canManagePerson(viewer.role, person);
  const lastOwnerDevice = person.role === "owner" && !device.wireguard_only && managedDevices(person).length === 1;
  const paused = person.suspended ? blocked(t("devices.gate.resumeFirst", { name: person.name })) : open;
  return {
    rename: manage ? open : null,
    peer: canActOnOwn(viewer.role, person, viewer.selfId, "manage_own_peer_communication") ? open : null,
    pairs: viewer.caps.devicePairs && canActOnOwn(viewer.role, person, viewer.selfId, "manage_own_peer_communication") ? open : null,
    localNetworks: viewer.caps.subnetRoutes && viewer.role === "owner" && person.role === "owner" ? open : null,
    portForwards: viewer.caps.portForwards && canActOnOwn(viewer.role, person, viewer.selfId, "manage_own_port_forwards") ? paused : null,
    remove: !manage ? null : lastOwnerDevice ? blocked(t("devices.gate.lastOwnerDevice")) : open,
  };
}

/** The devices this viewer may pair with: the VPS needs the same authority over both. */
export function pairCandidates(viewer: Viewer, snapshot: MembershipSnapshot, deviceId: string): DeviceSummary[] {
  return snapshot.members
    .filter((person) => canActOnOwn(viewer.role, person, viewer.selfId, "manage_own_peer_communication"))
    .flatMap((person) => person.devices)
    .filter((device) => device.id !== deviceId);
}

export const canCancel = (viewer: Viewer, code: ActiveInvitationSummary, snapshot: MembershipSnapshot) =>
  canCancelJoinCode(viewer.role, code, snapshot.members, viewer.selfId);

/** What the page's Add device button offers; `reason` explains an absent button. */
export function addDeviceEntry(viewer: Viewer, snapshot: MembershipSnapshot) {
  const self = selfPerson(snapshot, viewer.currentDeviceId);
  const mine = self ? addDeviceGate(viewer, self) : null;
  // A blocked person (suspended, at their limit) says why on their own group, not in the wizard's list.
  const people = snapshot.members.filter((person) => { const gate = person !== self ? addDeviceGate(viewer, person) : null; return gate !== null && !gate.blocked; });
  const roles = newPersonRoles(viewer, self);
  const any = mine !== null || people.length > 0 || roles.length > 0;
  return { self, mine, people, roles, any, reason: any ? null : t("devices.page.cannotAdd") };
}

/** Exactly what removing a person deletes, counted from the list. */
export function removalCounts(snapshot: MembershipSnapshot, person: MemberSummary) {
  const ids = new Set(person.devices.map((device) => device.id));
  return {
    devices: person.devices.length,
    forwards: (snapshot.port_forwards ?? []).filter((forward) => ids.has(forward.device_id)).length,
    pairs: (snapshot.device_pairs ?? []).filter((pair) => ids.has(pair.device_id) || ids.has(pair.peer_device_id)).length,
    codes: codesFor(snapshot, person.id).length,
  };
}
