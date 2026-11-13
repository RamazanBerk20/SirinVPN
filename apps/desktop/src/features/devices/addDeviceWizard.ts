import type { InvitationResult, MembershipSnapshot, WireGuardDeviceResult } from "../../types";
import { policyDraft, policyProblems, type PolicyDraft } from "./memberPolicy";
import type { Capabilities, Whose } from "./model";
import { deviceNameProblem, personNameProblem } from "./names";

export interface NewPerson {
  name: string;
  role: "member" | "admin";
  /** One code for several new people, who each name themselves. */
  several: boolean;
  people: number;
  policy: PolicyDraft;
}

export interface WizardDraft {
  whose: Whose | null;
  newPerson: NewPerson;
  method: "app" | "wireguard";
  /** Seconds until the code expires. */
  lifetime: 3600 | 86400 | 604800;
  /** Devices one code can add for an existing person. */
  uses: number;
  /** For a WireGuard configuration, or a code the joiner can't name. */
  deviceName: string;
  wireguardPath: string;
}

export type JoinStatus = "waiting" | "joined" | "expired" | "cancelled" | "ended";

export type Handover =
  | { kind: "code"; result: InvitationResult; maxUses: number;
    /** The existing person the code adds a device for; null for someone new. */
    personId: string | null;
    /** A Member sees only themselves, so someone new joining is invisible to them. */
    seesEveryone: boolean;
    /** Devices and people that existed when the code was made. */
    baseline: { devices: string[]; people: string[] };
    /** The code appeared in a list read after it was made, so its absence later means something. */
    seen: boolean; joined: string[]; status: JoinStatus; shared: boolean }
  | { kind: "wireguard"; result: WireGuardDeviceResult; deviceName: string; path: string; status: "waiting" | "joined" };

export type WizardState =
  | { step: "whose"; draft: WizardDraft; error: string | null }
  | { step: "connect"; draft: WizardDraft; error: string | null }
  | { step: "creating"; draft: WizardDraft }
  | { step: "handover"; draft: WizardDraft; handover: Handover };

export type WizardEvent =
  | { type: "choose"; whose: Whose }
  | { type: "editPerson"; patch: Partial<NewPerson> }
  | { type: "edit"; patch: Partial<Omit<WizardDraft, "whose" | "newPerson">> }
  | { type: "next" }
  | { type: "back" }
  | { type: "create" }
  | { type: "failed"; error: string }
  /** The VPS refused the new person's name: back to the name field, which shows `error`. */
  | { type: "nameTaken"; error: string }
  | { type: "createdCode"; result: InvitationResult; snapshot: MembershipSnapshot; personId: string | null; seesEveryone: boolean }
  | { type: "createdWireGuard"; result: WireGuardDeviceResult }
  | { type: "shared" }
  | { type: "snapshot"; snapshot: MembershipSnapshot; now: number };

export function startWizard(preset: Whose | null, inheritedPolicy?: Partial<PolicyDraft["policy"]>): WizardState {
  const draft: WizardDraft = {
    whose: preset,
    newPerson: { name: "", role: "member", several: false, people: 2, policy: policyDraft(inheritedPolicy) },
    method: "app", lifetime: 86400, uses: 1, deviceName: "", wireguardPath: "",
  };
  // A preset person skips the first question; the back button still offers it.
  return preset && preset.kind !== "new" ? { step: "connect", draft, error: null } : { step: "whose", draft, error: null };
}

/** Why the first step can't continue, or null. */
export function whoseProblem(draft: WizardDraft): string | null {
  if (!draft.whose) return "choose";
  if (draft.whose.kind !== "new") return null;
  const person = draft.newPerson;
  if (!person.several && personNameProblem(person.name)) return "name";
  if (person.several && (!Number.isInteger(person.people) || person.people < 2 || person.people > 100)) return "people";
  if (person.role === "member" && Object.keys(policyProblems(person.policy)).length > 0) return "policy";
  return null;
}

/** Why the second step can't create, or null. `needsDeviceName` comes from the server's naming support. */
export function connectProblem(draft: WizardDraft, needsDeviceName: boolean): string | null {
  if (draft.method === "wireguard" || needsDeviceName) {
    if (deviceNameProblem(draft.deviceName)) return "deviceName";
  }
  if (draft.method === "app" && (!Number.isInteger(draft.uses) || draft.uses < 1 || draft.uses > 100)) return "uses";
  return null;
}

/** The joiner can't name things on this server, so the issuer names the device now. */
export function needsDeviceName(draft: WizardDraft, caps: Pick<Capabilities, "recipientNames" | "namedCodes">): boolean {
  if (!caps.recipientNames) return true;
  // Until codes can carry a new person's name, a single new person's code fixes both names.
  return draft.whose?.kind === "new" && !draft.newPerson.several && !caps.namedCodes;
}

/** `fixed_member_name`: only a single new person's code, with joiner-named devices, on a server with named codes. */
export function fixesPersonName(draft: WizardDraft, caps: Pick<Capabilities, "recipientNames" | "namedCodes">): boolean {
  return draft.whose?.kind === "new" && !draft.newPerson.several && caps.namedCodes && !needsDeviceName(draft, caps);
}

/** Devices that appeared for the code's person (or new people) since the code was made. */
function joinedSince(handover: Extract<Handover, { kind: "code" }>, snapshot: MembershipSnapshot): string[] {
  const devices = new Set(handover.baseline.devices), people = new Set(handover.baseline.people);
  // shortcut: matches by person, not by code, so another code for the same person at the same moment counts too; exact once codes report their redemptions.
  return snapshot.members
    .filter((person) => handover.personId ? person.id === handover.personId : !people.has(person.id))
    .flatMap((person) => person.devices.filter((device) => !devices.has(device.id)).map((device) => device.name));
}

export function wizardReducer(state: WizardState, event: WizardEvent): WizardState {
  switch (event.type) {
    case "choose":
      return state.step === "whose" ? { ...state, draft: { ...state.draft, whose: event.whose,
        // Several new people can't share one WireGuard configuration.
        method: event.whose.kind === "new" && state.draft.newPerson.several ? "app" : state.draft.method }, error: null } : state;
    case "editPerson": {
      if (state.step !== "whose") return state;
      const newPerson = { ...state.draft.newPerson, ...event.patch };
      return { ...state, draft: { ...state.draft, newPerson, method: newPerson.several ? "app" : state.draft.method }, error: null };
    }
    case "edit":
      return state.step === "whose" || state.step === "connect" ? { ...state, draft: { ...state.draft, ...event.patch }, error: null } : state;
    case "next":
      return state.step === "whose" && !whoseProblem(state.draft) ? { step: "connect", draft: state.draft, error: null } : state;
    case "back":
      return state.step === "connect" ? { step: "whose", draft: state.draft, error: null } : state;
    case "create":
      return state.step === "connect" ? { step: "creating", draft: state.draft } : state;
    case "failed":
      return state.step === "creating" ? { step: "connect", draft: state.draft, error: event.error } : state;
    case "nameTaken":
      return state.step === "creating" ? { step: "whose", draft: state.draft, error: event.error } : state;
    case "createdCode": {
      if (state.step !== "creating") return state;
      const { draft } = state;
      const people = draft.whose?.kind === "new" && draft.newPerson.several ? draft.newPerson.people : 1;
      return { step: "handover", draft, handover: {
        kind: "code", result: event.result, personId: event.personId, seesEveryone: event.seesEveryone,
        maxUses: draft.whose?.kind === "new" ? people : draft.uses,
        baseline: { devices: event.snapshot.members.flatMap((person) => person.devices.map((device) => device.id)), people: event.snapshot.members.map((person) => person.id) },
        seen: false, joined: [], status: "waiting", shared: false,
      } };
    }
    case "createdWireGuard":
      return state.step === "creating" ? { step: "handover", draft: state.draft, handover: {
        kind: "wireguard", result: event.result, deviceName: state.draft.deviceName.trim(), path: state.draft.wireguardPath, status: "waiting",
      } } : state;
    case "shared":
      return state.step === "handover" && state.handover.kind === "code" ? { ...state, handover: { ...state.handover, shared: true } } : state;
    case "snapshot": {
      if (state.step !== "handover") return state;
      const handover = state.handover;
      if (handover.kind === "wireguard") {
        const device = event.snapshot.members.flatMap((person) => person.devices).find((entry) => entry.id === handover.result.device_id);
        return device?.recent_handshake ? { ...state, handover: { ...handover, status: "joined" } } : state;
      }
      if (handover.status !== "waiting") return state;
      const active = event.snapshot.active_invitations.some((code) => code.id === handover.result.invitation_id);
      const joined = joinedSince(handover, event.snapshot);
      if (active) return { ...state, handover: { ...handover, seen: true, joined } };
      // A list read before the code existed says nothing about it.
      if (!handover.seen && joined.length === 0 && event.now < handover.result.expires_at_unix * 1000) return state;
      const status: JoinStatus = joined.length > 0 ? "joined"
        : event.now >= handover.result.expires_at_unix * 1000 ? "expired"
          : handover.personId === null && !handover.seesEveryone ? "ended" : "cancelled";
      return { ...state, handover: { ...handover, seen: true, joined, status } };
    }
  }
}
