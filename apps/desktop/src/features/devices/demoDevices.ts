import type { ActiveInvitationSummary, CurrentConfiguration, DeviceSummary, MemberPolicy, MemberSummary, MembershipSnapshot } from "../../types";

/**
 * The demo's people and devices: a small server that answers the Devices commands in memory.
 * `sessionStorage["sirin.demo.role"]` ("owner", "admin" or "member") picks who you are;
 * `sessionStorage["sirin.demo.future"] = "1"` turns on server features that aren't released yet.
 */
type Role = "owner" | "admin" | "member";
const role = (() => { try { return (sessionStorage.getItem("sirin.demo.role") as Role) || "owner"; } catch { return "owner" as Role; } })();
const future = (() => { try { return sessionStorage.getItem("sirin.demo.future") === "1"; } catch { return false; } })();

// The fixture's own profile: this device and its person.
const SELF = "223e4567-e89b-42d3-a456-426614174000";
const THIS_DEVICE = "323e4567-e89b-42d3-a456-426614174000";
const fingerprint = (letter: string) => "SHA256:" + letter.repeat(43);
const blank: MemberPolicy = { device_limit: null, expires_at_unix: null, weekly_access: [], invite_members: false, add_own_devices: false, manage_own_peer_communication: false, manage_own_port_forwards: false };
const device = (id: string, member: string, name: string, address: number, extra: Partial<DeviceSummary> = {}): DeviceSummary =>
  ({ id, member_id: member, name, client_tunnel_address: `10.77.0.${address}`, identity_fingerprint: fingerprint(id[0].toUpperCase()), ...extra });

const self: MemberSummary = {
  id: SELF, name: "You", role: role === "owner" ? "owner" : "member", administrator: role === "admin",
  policy: role === "member" ? { ...blank, add_own_devices: true, manage_own_peer_communication: true } : undefined,
  devices: [device(THIS_DEVICE, SELF, "My Linux desktop", 2, { platform: "linux", recent_handshake: true }),
    device("pixel", SELF, "Pixel 9", 5, { platform: "android", recent_handshake: false, peer_communication_enabled: true })],
};
const others: MemberSummary[] = [
  ...(role === "owner" ? [] : [{ id: "owner", name: "Deniz", role: "owner" as const, devices: [
    device("router", "owner", "Home router", 6, { subnet_routes: ["192.168.1.0/24"], peer_communication_enabled: true, recent_handshake: true }),
    device("macbook", "owner", "MacBook", 7, { wireguard_only: true })] }]),
  { id: "ayse", name: "Ayşe", role: "member", administrator: role !== "admin", devices: [device("ayse-laptop", "ayse", "Ayşe’s laptop", 8, { platform: "windows", recent_handshake: true })] },
  { id: "family", name: "Family", role: "member", policy: { ...blank, device_limit: 3, weekly_access: [{ start_minute: 6 * 60, end_minute: 18 * 60 }, { start_minute: 1440 + 6 * 60, end_minute: 1440 + 18 * 60 }] },
    devices: [device("phone", "family", "Android phone", 3, { platform: "android", recent_handshake: true }), device("laptop", "family", "Work laptop", 4, { recent_handshake: false })] },
  { id: "mert", name: "Mert", role: "member", suspended: true, policy: { ...blank }, devices: [device("mert-phone", "mert", "Mert’s phone", 9)] },
];

const state: MembershipSnapshot = {
  members: [self, ...others],
  active_invitations: [{ id: "code-family", member_name: "Family", device_name: "", target_member_id: "family", recipient_names: true, expires_at_unix: Math.floor(Date.now() / 1000) + 3 * 3600, max_uses: 1, uses_remaining: 1 }],
  port_forwards: [{ protocol: "tcp", public_port: 8443, device_id: "router", device_port: 443 }],
  device_pairs: [{ device_id: "pixel", peer_device_id: "laptop", one_way: true }],
};
let address = 20;

const configuration: CurrentConfiguration = {
  port_forwarding_enabled: true, member_lifecycle_enabled: true, member_policies_enabled: true, reusable_invitations_enabled: true,
  recipient_names_enabled: true, wireguard_devices_enabled: true, subnet_routes_enabled: true, device_pairs_enabled: true,
  ...(future ? { named_join_codes_enabled: true, person_rename_enabled: true, admin_own_devices_enabled: true } : {}),
};

const copy = () => structuredClone(state);
/** What this role is shown: a Member sees only themselves and the codes they made. */
const visible = (): MembershipSnapshot => role !== "member" ? copy() : {
  ...copy(), members: copy().members.filter((person) => person.id === SELF),
  active_invitations: [], device_pairs: (state.device_pairs ?? []).filter((pair) => [pair.device_id, pair.peer_device_id].some((id) => self.devices.some((entry) => entry.id === id))),
  port_forwards: (state.port_forwards ?? []).filter((forward) => self.devices.some((entry) => entry.id === forward.device_id)),
};
const person = (id: string) => { const found = state.members.find((entry) => entry.id === id); if (!found) throw new Error("member was not found"); return found; };
const findDevice = (id: string) => { for (const entry of state.members) { const found = entry.devices.find((candidate) => candidate.id === id); if (found) return found; } throw new Error("device was not found"); };
const removeDevices = (ids: string[]) => {
  state.port_forwards = (state.port_forwards ?? []).filter((forward) => !ids.includes(forward.device_id));
  state.device_pairs = (state.device_pairs ?? []).filter((pair) => !ids.includes(pair.device_id) && !ids.includes(pair.peer_device_id));
};
const qr = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 21 21"><rect width="21" height="21" fill="#fff"/><path d="M1 1h7v7H1zM13 1h7v7h-7zM1 13h7v7H1zM10 10h2v2h-2z" fill="#000"/></svg>';

/** A demo join: the device appears a few seconds after the code is made, unless it was cancelled. */
function joinLater(code: ActiveInvitationSummary, deviceName: string) {
  window.setTimeout(() => {
    if (!state.active_invitations.some((entry) => entry.id === code.id)) return;
    state.active_invitations = state.active_invitations.filter((entry) => entry.id !== code.id);
    const id = `joined-${code.id}`;
    const joined = device(id, code.target_member_id ?? id, deviceName, address++, { recent_handshake: true, platform: "android" });
    if (code.target_member_id) person(code.target_member_id).devices.push(joined);
    else state.members.push({ id, name: code.recipient_names && code.member_name === "" ? "Joiner" : code.member_name, role: "member", administrator: code.administrator, policy: code.member_policy, devices: [joined] });
  }, 8_000);
}

export function demoDevices(command: string, args: Record<string, unknown>): { handled: true; value: unknown } | { handled: false } {
  const input = (args.input ?? {}) as Record<string, unknown>;
  const answer = (value: unknown) => ({ handled: true as const, value });
  switch (command) {
    case "server_configuration": return answer(configuration);
    case "membership": return answer(visible());
    case "create_invitation": {
      const target = input.target_member_id as string | null;
      // The VPS rules the demo exercises: fixed names only for one new named person, and an Admin's own devices only on newer servers.
      if (input.fixed_member_name && (!future || target || !input.recipient_names || Number(input.max_uses ?? 1) !== 1 || !input.member_name)) throw new Error("a fixed member name needs one new person, a name and recipient-named devices");
      if (target === SELF && role === "admin" && !future) throw new Error("only managers can add devices for this member");
      if (target && Boolean(input.administrator) !== Boolean(person(target).administrator)) throw new Error("the invitation's access level does not match the member");
      const code: ActiveInvitationSummary = {
        id: `code-${Date.now()}`, member_name: target ? person(target).name : input.member_name as string, device_name: input.device_name as string,
        target_member_id: target ?? undefined, administrator: Boolean(input.administrator), recipient_names: Boolean(input.recipient_names),
        expires_at_unix: Math.floor(Date.now() / 1000) + Number(input.expires_in_seconds), max_uses: Number(input.max_uses ?? 1), uses_remaining: Number(input.max_uses ?? 1),
        member_policy: input.member_policy as MemberPolicy | undefined, issued_by_member_id: future ? SELF : undefined,
      };
      state.active_invitations.push(code);
      joinLater(code, (input.device_name as string) || "Galaxy S25");
      return answer({ invitation_id: code.id, expires_at_unix: code.expires_at_unix, code: `sirin1.demo-${code.id}`, qr_svg: qr });
    }
    case "create_wireguard_device": {
      const id = `wg-${Date.now()}`, target = input.target_member_id as string | null;
      const added = device(id, target ?? id, input.device_name as string, address++, { wireguard_only: true });
      if (target) person(target).devices.push(added);
      else state.members.push({ id, name: input.member_name as string, role: "member", policy: input.member_policy as MemberPolicy | undefined, devices: [added] });
      window.setTimeout(() => { added.recent_handshake = true; }, 8_000);
      return answer({ device_id: id, qr_svg: qr });
    }
    case "cancel_invitation": state.active_invitations = state.active_invitations.filter((code) => code.id !== args.invitationId); return answer(undefined);
    case "rename_device": findDevice(input.device_id as string).name = input.name as string; return answer(visible());
    case "rename_member": {
      if (!future) throw new Error("Update the server to rename people.");
      if (state.active_invitations.some((code) => code.target_member_id === input.member_id))
        throw Object.assign(new Error("cancel the member's active device invitations before renaming them"), { code: "person_has_join_codes", params: {} });
      person(input.member_id as string).name = input.name as string; return answer(visible());
    }
    case "revoke_device": {
      for (const entry of state.members) entry.devices = entry.devices.filter((candidate) => candidate.id !== args.deviceId);
      removeDevices([args.deviceId as string]); return answer(visible());
    }
    case "update_device_peer_communication": findDevice(input.device_id as string).peer_communication_enabled = Boolean(input.enabled); return answer(visible());
    case "set_device_pair": {
      const pairs = (state.device_pairs ?? []).filter((pair) => ![pair.device_id, pair.peer_device_id].every((id) => id === input.device_id || id === input.peer_device_id));
      state.device_pairs = [...pairs, { device_id: input.device_id as string, peer_device_id: input.peer_device_id as string, one_way: Boolean(input.one_way) || undefined }];
      return answer(visible());
    }
    case "remove_device_pair": state.device_pairs = (state.device_pairs ?? []).filter((pair) => !(pair.device_id === input.device_id && pair.peer_device_id === input.peer_device_id)); return answer(visible());
    case "update_device_subnet_routes": findDevice(input.device_id as string).subnet_routes = input.routes as string[]; return answer(visible());
    case "create_port_forward": {
      if ((state.port_forwards ?? []).some((forward) => forward.public_port === input.public_port && forward.protocol === input.protocol)) throw new Error("public port is already forwarded");
      state.port_forwards = [...(state.port_forwards ?? []), { protocol: input.protocol as "tcp", public_port: Number(input.public_port), device_id: input.device_id as string, device_port: Number(input.device_port) }];
      return answer(visible());
    }
    case "remove_port_forward": state.port_forwards = (state.port_forwards ?? []).filter((forward) => !(forward.protocol === input.protocol && forward.public_port === input.public_port)); return answer(visible());
    case "update_member_policy": person(input.member_id as string).policy = input.policy as MemberPolicy; state.active_invitations = state.active_invitations.filter((code) => code.target_member_id !== input.member_id); return answer(visible());
    case "update_member_access": {
      if (state.active_invitations.some((code) => code.target_member_id === input.member_id)) throw new Error("wait for recent enrollment handoffs and cancel active device invitations before changing access");
      person(input.member_id as string).administrator = Boolean(input.administrator); return answer(visible());
    }
    case "update_member_suspension": {
      person(input.member_id as string).suspended = Boolean(input.suspended) || undefined;
      if (input.suspended) state.active_invitations = state.active_invitations.filter((code) => code.target_member_id !== input.member_id);
      return answer(visible());
    }
    case "revoke_member_devices": {
      const removed = person(input.member_id as string);
      removeDevices(removed.devices.map((entry) => entry.id));
      state.members = state.members.filter((entry) => entry !== removed);
      state.active_invitations = state.active_invitations.filter((code) => code.target_member_id !== removed.id);
      return answer(visible());
    }
    case "transfer_ownership": {
      const owner = state.members.find((entry) => entry.role === "owner")!;
      const next = state.members.find((entry) => entry.devices.some((candidate) => candidate.id === input.destination_device_id))!;
      owner.role = "member"; owner.administrator = true; next.role = "owner"; next.administrator = false;
      return answer(visible());
    }
    default: return { handled: false };
  }
}

/** The status the fixture reports for this device follows the chosen role. */
export const demoCaller = { caller_role: role === "owner" ? "owner" : "member", caller_administrator: role === "admin" };
