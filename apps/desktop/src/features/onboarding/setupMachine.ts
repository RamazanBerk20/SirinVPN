import type { AppError } from "../../lib/errors";
import type { NetworkPreflight, ProvisionResult } from "../../types";

/** A host key the user saw for `target` (host:port), and the network check run for `network` (target + transport). */
export interface Verified {
  target: string;
  fingerprint: string;
  /** Only a successful network check counts: it is also when the fingerprint was confirmed. */
  checked: { network: string; preflight: NetworkPreflight } | null;
}

export type SetupState =
  | { kind: "editing"; verified: Verified | null; error: string | null }
  | { kind: "probing"; target: string }
  | { kind: "verifying"; verified: Verified; error: string | null }
  /** `from` is where a failed check returns: the created-server form or the fingerprint step. */
  | { kind: "checkingNetwork"; verified: Verified; network: string; from: "editing" | "verifying" }
  | { kind: "reviewed"; verified: Verified & { checked: NonNullable<Verified["checked"]> }; error: string | null }
  | { kind: "installing"; verified: Verified }
  | { kind: "failed"; verified: Verified; error: AppError }
  | { kind: "done"; result: ProvisionResult };

export type SetupEvent =
  /** Continue from the form: reuses a verified key (and network check) for the same target, else probes. */
  | { type: "submit"; target: string; network: string }
  | { type: "probed"; fingerprint: string }
  | { type: "probeFailed"; error: string }
  /** A created server's pinned key goes straight to the network check. */
  | { type: "checkNetwork"; network: string; pinned?: { target: string; fingerprint: string } }
  | { type: "checked"; preflight: NetworkPreflight }
  | { type: "checkFailed"; error: string }
  | { type: "install" }
  | { type: "installed"; result: ProvisionResult }
  | { type: "installFailed"; error: AppError }
  | { type: "back" };

export const initialSetup: SetupState = { kind: "editing", verified: null, error: null };

export function setupReducer(state: SetupState, event: SetupEvent): SetupState {
  switch (event.type) {
    case "submit": {
      if (state.kind !== "editing") return state;
      const verified = state.verified;
      if (verified?.target !== event.target) return { kind: "probing", target: event.target };
      // A check of another network (ports changed) no longer applies.
      return verified.checked?.network === event.network
        ? { kind: "reviewed", verified: verified as Verified & { checked: NonNullable<Verified["checked"]> }, error: null }
        : { kind: "verifying", verified: { ...verified, checked: null }, error: null };
    }
    case "probed":
      return state.kind === "probing" ? { kind: "verifying", verified: { target: state.target, fingerprint: event.fingerprint, checked: null }, error: null } : state;
    case "probeFailed":
      return state.kind === "probing" ? { kind: "editing", verified: null, error: event.error } : state;
    case "checkNetwork":
      if (state.kind === "verifying" || state.kind === "reviewed") return { kind: "checkingNetwork", verified: state.verified, network: event.network, from: "verifying" };
      if (state.kind === "editing" && event.pinned) return { kind: "checkingNetwork", verified: { ...event.pinned, checked: null }, network: event.network, from: "editing" };
      return state;
    case "checked":
      return state.kind === "checkingNetwork"
        ? { kind: "reviewed", verified: { ...state.verified, checked: { network: state.network, preflight: event.preflight } }, error: null } : state;
    case "checkFailed":
      if (state.kind !== "checkingNetwork") return state;
      return state.from === "editing"
        ? { kind: "editing", verified: { ...state.verified, checked: null }, error: event.error }
        : { kind: "verifying", verified: { ...state.verified, checked: null }, error: event.error };
    case "install":
      return state.kind === "reviewed" || state.kind === "failed" ? { kind: "installing", verified: state.verified } : state;
    case "installed":
      return state.kind === "installing" ? { kind: "done", result: event.result } : state;
    case "installFailed":
      return state.kind === "installing" ? { kind: "failed", verified: state.verified, error: event.error } : state;
    case "back":
      return state.kind === "verifying" || state.kind === "reviewed" || state.kind === "failed"
        ? { kind: "editing", verified: state.verified, error: null } : state;
  }
}

export type SetupStep = "details" | "fingerprint" | "installing" | "failed" | "success";

/** The step a parent needs (e.g. to hide its own Back past the first step). */
export function setupStep(state: SetupState): SetupStep {
  switch (state.kind) {
    case "editing": case "probing": return "details";
    case "checkingNetwork": return state.from === "editing" ? "details" : "fingerprint";
    case "verifying": case "reviewed": return "fingerprint";
    case "installing": return "installing";
    case "failed": return "failed";
    case "done": return "success";
  }
}
