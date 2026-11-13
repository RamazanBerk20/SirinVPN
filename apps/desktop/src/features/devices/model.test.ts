import { describe, expect, it } from "vitest";
import type { MemberPolicy, MemberSummary, MembershipSnapshot } from "../../types";
import { defaultMemberPolicy } from "./memberPolicy";
import {
  addDeviceEntry, capabilities, deviceSummary, devicePermissions, groupPeople, pageReducer, personPermissions, presence,
  removalCounts, type Capabilities, type PageState, type Viewer,
} from "./model";

const all: Capabilities = capabilities({
  member_lifecycle_enabled: true, reusable_invitations_enabled: true, recipient_names_enabled: true, wireguard_devices_enabled: true,
  subnet_routes_enabled: true, device_pairs_enabled: true, port_forwarding_enabled: true,
}, false);
const policy = (patch: Partial<MemberPolicy>): MemberPolicy => ({ ...defaultMemberPolicy(), ...patch });
const device = (id: string, member: string, extra = {}) => ({ id, member_id: member, name: id, client_tunnel_address: `10.77.0.${id.length}`, ...extra });

const owner: MemberSummary = { id: "o", name: "Deniz", role: "owner", devices: [device("o-laptop", "o"), device("o-phone", "o")] };
const admin: MemberSummary = { id: "a", name: "Ayşe", role: "member", administrator: true, devices: [device("a-laptop", "a")] };
const member: MemberSummary = { id: "m", name: "Mert", role: "member", devices: [device("m-phone", "m")] };
const snapshot: MembershipSnapshot = { members: [member, owner, admin], active_invitations: [], port_forwards: [], device_pairs: [] };

const viewer = (role: Viewer["role"], self: MemberSummary, caps = all): Viewer => ({ role, selfId: self.id, currentDeviceId: self.devices[0].id, caps });
const shown = (gate: unknown) => gate !== null;

describe("page model", () => {
  it("moves through loading, ready, stale and disconnected without losing the saved list", () => {
    let state: PageState = { kind: "loading" };
    state = pageReducer(state, { type: "loaded", snapshot, configuration: { member_lifecycle_enabled: true }, android: false, at: 1 });
    expect(state.kind).toBe("ready");
    state = pageReducer(state, { type: "refreshing" });
    expect(state).toMatchObject({ kind: "ready", refreshing: true });
    state = pageReducer(state, { type: "failed", error: "down", at: 5 });
    expect(state).toMatchObject({ kind: "stale", at: 1, error: "down" });
    expect(pageReducer(state, { type: "changed", snapshot, at: 6 })).toBe(state);
    expect(pageReducer({ kind: "loading" }, { type: "failed", error: "down", at: 1 })).toMatchObject({ kind: "failed" });
    expect(pageReducer(state, { type: "disconnected", saved: { snapshot, at: 1 } })).toMatchObject({ kind: "disconnected", saved: { at: 1 } });
  });

  it("forgets activity in a list it can no longer refresh", () => {
    const active = { ...snapshot, members: [{ ...member, devices: [device("m-phone", "m", { recent_handshake: true })] }] };
    const ready = pageReducer({ kind: "loading" }, { type: "loaded", snapshot: active, configuration: { member_lifecycle_enabled: true }, android: false, at: 1 });
    const stale = pageReducer(ready, { type: "failed", error: "down", at: 2 });
    expect(stale.kind === "stale" && stale.snapshot.members[0].devices[0].recent_handshake).toBeUndefined();
  });

  it("calls a server without people management unsupported", () => {
    expect(pageReducer({ kind: "loading" }, { type: "loaded", snapshot, configuration: {}, android: false, at: 1 }).kind).toBe("unsupported");
  });

  it("hides WireGuard devices on Android", () => {
    expect(capabilities({ wireguard_devices_enabled: true }, true).wireguard).toBe(false);
  });

  it("puts My devices first, then the Owner, Admins and Members", () => {
    const { self, others } = groupPeople(snapshot, "m-phone");
    expect(self?.id).toBe("m");
    expect(others.map((person) => person.id)).toEqual(["o", "a"]);
  });

  it("uses one presence rule for every device", () => {
    expect(presence({}, { recent_handshake: true })).toBe("active");
    expect(presence({}, { recent_handshake: false })).toBe("idle");
    expect(presence({}, {})).toBe("unknown");
    expect(presence({ suspended: true }, { recent_handshake: true })).toBe("suspended");
  });

  it("summarises what a device can do in one line", () => {
    const router = device("router", "o", { peer_communication_enabled: true, subnet_routes: ["192.168.1.0/24"] });
    const forwards = { ...snapshot, port_forwards: [{ protocol: "tcp" as const, public_port: 8443, device_id: "router", device_port: 443 }] };
    expect(deviceSummary(forwards, router)).toBe("SirinVPN app · reaches other devices · shares 192.168.1.0/24 · 1 forwarded port");
    expect(deviceSummary(snapshot, device("wg", "o", { wireguard_only: true }))).toBe("WireGuard app · internet only");
  });

  it("counts exactly what removing a person deletes", () => {
    const linked = { ...snapshot,
      port_forwards: [{ protocol: "udp" as const, public_port: 5000, device_id: "m-phone", device_port: 5000 }],
      device_pairs: [{ device_id: "m-phone", peer_device_id: "o-laptop" }],
      active_invitations: [{ id: "c", member_name: "Mert", device_name: "", target_member_id: "m", expires_at_unix: 9 }] };
    expect(removalCounts(linked, member)).toEqual({ devices: 1, forwards: 1, pairs: 1, codes: 1 });
  });
});

describe("who sees which action", () => {
  it("gives the Owner every person action except on themselves", () => {
    const as = viewer("owner", owner);
    expect(Object.entries(personPermissions(as, member)).filter(([, gate]) => shown(gate)).map(([key]) => key))
      .toEqual(["addDevice", "role", "makeOwner", "limits", "suspend", "remove"]);
    expect(Object.entries(personPermissions(as, owner)).filter(([, gate]) => shown(gate)).map(([key]) => key)).toEqual(["addDevice"]);
    expect(shown(personPermissions(as, admin).limits)).toBe(true);
  });

  it("lets an Admin manage Members but not Admins or the Owner, and never roles", () => {
    const as = viewer("admin", admin);
    const forMember = personPermissions(as, member);
    expect([forMember.addDevice, forMember.limits, forMember.suspend, forMember.remove].every(shown)).toBe(true);
    expect(shown(forMember.role) || shown(forMember.makeOwner)).toBe(false);
    expect(Object.values(personPermissions(as, owner)).some(shown)).toBe(false);
    expect(Object.values(personPermissions({ ...as, selfId: "other" }, admin)).some(shown)).toBe(false);
  });

  it("lets an Admin add their own device only where the server allows it", () => {
    expect(personPermissions(viewer("admin", admin), admin).addDevice).toBeNull();
    expect(personPermissions(viewer("admin", { ...admin, policy: policy({ add_own_devices: true }) }), { ...admin, policy: policy({ add_own_devices: true }) }).addDevice).toEqual({});
    expect(personPermissions(viewer("admin", admin, { ...all, adminOwnDevices: true }), admin).addDevice).toEqual({});
  });

  it("gives a Member only what their permissions allow, on their own devices", () => {
    const plain = viewer("member", member);
    expect(Object.values(personPermissions(plain, member)).some(shown)).toBe(false);
    expect(Object.values(devicePermissions(plain, member, member.devices[0])).some(shown)).toBe(false);
    const allowed = { ...member, policy: policy({ add_own_devices: true, manage_own_peer_communication: true, manage_own_port_forwards: true }) };
    const as = viewer("member", allowed);
    expect(personPermissions(as, allowed).addDevice).toEqual({});
    const own = devicePermissions(as, allowed, allowed.devices[0]);
    expect([own.peer, own.pairs, own.portForwards].every(shown)).toBe(true);
    expect([own.rename, own.remove, own.localNetworks].some(shown)).toBe(false);
  });

  it("explains blocked actions instead of hiding them", () => {
    const as = viewer("owner", owner);
    expect(devicePermissions(as, { ...owner, devices: [owner.devices[0]] }, owner.devices[0]).remove?.blocked).toBeTruthy();
    expect(personPermissions(as, { ...member, suspended: true }).addDevice?.blocked).toBeTruthy();
    expect(personPermissions(as, { ...member, policy: policy({ device_limit: 1 }) }).addDevice?.blocked).toBeTruthy();
    expect(personPermissions(as, { ...member, devices: [device("wg", "m", { wireguard_only: true })] }).makeOwner?.blocked).toBeTruthy();
    expect(devicePermissions(as, { ...member, suspended: true }, member.devices[0]).portForwards?.blocked).toBeTruthy();
  });

  it("offers local networks only on the Owner's own devices, and rename person only when the server can", () => {
    const as = viewer("owner", owner);
    expect(shown(devicePermissions(as, owner, owner.devices[0]).localNetworks)).toBe(true);
    expect(shown(devicePermissions(as, member, member.devices[0]).localNetworks)).toBe(false);
    expect(personPermissions(as, member).rename).toBeNull();
    expect(personPermissions({ ...as, caps: { ...all, renamePerson: true } }, member).rename).toEqual({});
  });

  it("builds Add device from the same rules, with a reason when nothing is possible", () => {
    expect(addDeviceEntry(viewer("owner", owner), snapshot)).toMatchObject({ any: true, roles: ["member", "admin"], mine: {} });
    expect(addDeviceEntry(viewer("admin", admin), snapshot)).toMatchObject({ any: true, roles: ["member"], mine: null });
    const alone = { ...snapshot, members: [member] };
    const none = addDeviceEntry(viewer("member", member), alone);
    expect(none.any).toBe(false);
    expect(none.reason).toBeTruthy();
    const inviter = { ...member, policy: policy({ invite_members: true }) };
    expect(addDeviceEntry(viewer("member", inviter), { ...snapshot, members: [inviter] })).toMatchObject({ any: true, roles: ["member"], mine: null });
  });
});
