import { describe, expect, it } from "vitest";
import type { MembershipSnapshot } from "../../types";
import { connectProblem, fixesPersonName, needsDeviceName, startWizard, whoseProblem, wizardReducer, type WizardState } from "./addDeviceWizard";

const code = { invitation_id: "code-1", expires_at_unix: 2_000, code: "sirin1.secret", qr_svg: "<svg/>" };
const base: MembershipSnapshot = {
  members: [{ id: "o", name: "Deniz", role: "owner", devices: [{ id: "laptop", member_id: "o", name: "Laptop", client_tunnel_address: "10.77.0.2" }] }],
  active_invitations: [],
};
const withCode = { ...base, active_invitations: [{ id: "code-1", member_name: "Deniz", device_name: "", target_member_id: "o", expires_at_unix: 2_000 }] };
const joined: MembershipSnapshot = { ...base, members: [{ ...base.members[0], devices: [...base.members[0].devices, { id: "phone", member_id: "o", name: "Pixel", client_tunnel_address: "10.77.0.3" }] }] };

function created(personId: string | null, seesEveryone = true): WizardState {
  let state = startWizard({ kind: "self" });
  state = wizardReducer(state, { type: "create" });
  return wizardReducer(state, { type: "createdCode", result: code, snapshot: base, personId, seesEveryone });
}

describe("add-device wizard", () => {
  it("starts at the question it can't answer for itself", () => {
    expect(startWizard(null).step).toBe("whose");
    expect(startWizard({ kind: "new" }).step).toBe("whose");
    expect(startWizard({ kind: "person", personId: "m" }).step).toBe("connect");
  });

  it("needs a name and valid limits for someone new, but not for several people", () => {
    let state = wizardReducer(startWizard(null), { type: "choose", whose: { kind: "new" } });
    expect(whoseProblem(state.draft)).toBe("name");
    expect(wizardReducer(state, { type: "next" }).step).toBe("whose");
    state = wizardReducer(state, { type: "editPerson", patch: { name: "Ayşe" } });
    expect(whoseProblem(state.draft)).toBeNull();
    expect(wizardReducer(state, { type: "next" }).step).toBe("connect");
    const several = wizardReducer(wizardReducer(state, { type: "editPerson", patch: { name: "", several: true } }), { type: "edit", patch: { method: "wireguard" } });
    expect(whoseProblem(several.draft)).toBeNull();
    const broken = wizardReducer(state, { type: "editPerson", patch: { policy: { ...state.draft.newPerson.policy, limit: "0" } } });
    expect(whoseProblem(broken.draft)).toBe("policy");
    // An Admin has no limits to check.
    expect(whoseProblem(wizardReducer(broken, { type: "editPerson", patch: { role: "admin" } }).draft)).toBeNull();
  });

  it("keeps several new people on the SirinVPN app", () => {
    let state = wizardReducer(startWizard(null), { type: "choose", whose: { kind: "new" } });
    state = wizardReducer(state, { type: "edit", patch: { method: "wireguard" } });
    state = wizardReducer(state, { type: "editPerson", patch: { several: true } });
    expect(state.draft.method).toBe("app");
  });

  it("asks for a device name only where the joiner can't give one", () => {
    const draft = startWizard({ kind: "self" }).draft;
    expect(connectProblem(draft, false)).toBeNull();
    expect(connectProblem(draft, true)).toBe("deviceName");
    expect(connectProblem({ ...draft, method: "wireguard" }, false)).toBe("deviceName");
    expect(connectProblem({ ...draft, uses: 0 }, false)).toBe("uses");
  });

  it("returns a failed creation to the form with its error", () => {
    const state = wizardReducer(wizardReducer(startWizard({ kind: "self" }), { type: "create" }), { type: "failed", error: "nope" });
    expect(state).toMatchObject({ step: "connect", error: "nope" });
  });

  it("returns a refused new-person name to the name field", () => {
    const state = wizardReducer(wizardReducer(startWizard({ kind: "self" }), { type: "create" }), { type: "nameTaken", error: "taken" });
    expect(state).toMatchObject({ step: "whose", error: "taken" });
    expect(wizardReducer(state, { type: "editPerson", patch: { name: "Other" } })).toMatchObject({ step: "whose", error: null });
  });

  it("waits, then reports the device that joined", () => {
    let state = created("o");
    expect(state).toMatchObject({ step: "handover", handover: { status: "waiting", seen: false } });
    // A list read before the code existed says nothing.
    state = wizardReducer(state, { type: "snapshot", snapshot: base, now: 1_000_000 });
    expect(state).toMatchObject({ handover: { status: "waiting", seen: false } });
    state = wizardReducer(state, { type: "snapshot", snapshot: withCode, now: 1_000_000 });
    expect(state).toMatchObject({ handover: { status: "waiting", seen: true } });
    state = wizardReducer(state, { type: "snapshot", snapshot: joined, now: 1_000_000 });
    expect(state).toMatchObject({ handover: { status: "joined", joined: ["Pixel"] } });
  });

  it("tells expiry from cancellation", () => {
    const seen = wizardReducer(created("o"), { type: "snapshot", snapshot: withCode, now: 1_000_000 });
    expect(wizardReducer(seen, { type: "snapshot", snapshot: base, now: 1_000_000 })).toMatchObject({ handover: { status: "cancelled" } });
    expect(wizardReducer(seen, { type: "snapshot", snapshot: base, now: 2_000_000 })).toMatchObject({ handover: { status: "expired" } });
  });

  it("doesn't claim a cancellation a Member can't see", () => {
    const seen = wizardReducer(created(null, false), { type: "snapshot", snapshot: { ...base, active_invitations: [{ ...withCode.active_invitations[0], target_member_id: undefined }] }, now: 1 });
    expect(wizardReducer(seen, { type: "snapshot", snapshot: base, now: 1 })).toMatchObject({ handover: { status: "ended" } });
  });

  it("marks a WireGuard device joined once it is seen connected", () => {
    let state = wizardReducer(startWizard({ kind: "self" }), { type: "edit", patch: { method: "wireguard", deviceName: "iPhone" } });
    state = wizardReducer(wizardReducer(state, { type: "create" }), { type: "createdWireGuard", result: { device_id: "phone", qr_svg: "<svg/>" } });
    expect(state).toMatchObject({ handover: { kind: "wireguard", status: "waiting", deviceName: "iPhone" } });
    const connected = { ...joined, members: [{ ...joined.members[0], devices: joined.members[0].devices.map((entry) => ({ ...entry, recent_handshake: true })) }] };
    expect(wizardReducer(state, { type: "snapshot", snapshot: connected, now: 1 })).toMatchObject({ handover: { status: "joined" } });
  });
});

describe("naming on the code", () => {
  const caps = { recipientNames: true, namedCodes: true };
  const draft = (whose: Parameters<typeof startWizard>[0], several = false) => {
    const state = startWizard(whose);
    return { ...state.draft, newPerson: { ...state.draft.newPerson, name: "Ayşe", several } };
  };

  it("fixes the person's name only for one new person on a server with named codes", () => {
    expect(fixesPersonName(draft({ kind: "new" }), caps)).toBe(true);
    expect(needsDeviceName(draft({ kind: "new" }), caps)).toBe(false);
    expect(fixesPersonName(draft({ kind: "new" }, true), caps)).toBe(false);
    expect(fixesPersonName(draft({ kind: "self" }), caps)).toBe(false);
    expect(fixesPersonName(draft({ kind: "person", personId: "m" }), caps)).toBe(false);
  });

  it("keeps the older behaviour without named codes or recipient names", () => {
    expect(fixesPersonName(draft({ kind: "new" }), { recipientNames: true, namedCodes: false })).toBe(false);
    expect(needsDeviceName(draft({ kind: "new" }), { recipientNames: true, namedCodes: false })).toBe(true);
    expect(fixesPersonName(draft({ kind: "new" }), { recipientNames: false, namedCodes: true })).toBe(false);
  });
});
