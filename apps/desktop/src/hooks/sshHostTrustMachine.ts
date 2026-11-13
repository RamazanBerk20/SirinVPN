import type { SshHostInspection } from "../types";

export interface InspectedSshHost extends SshHostInspection {
  host: string;
  port: number;
}

/**
 * Whether a VPS's SSH key may be used. The user's "I verified it" belongs to one inspection: any new
 * destination or inspection drops it. `seq` ties async results to the request that asked.
 */
export type HostTrustState =
  | { kind: "unchecked"; seq: number }
  | { kind: "checking"; seq: number }
  | { kind: "trusted"; seq: number; inspection: InspectedSshHost }
  | { kind: "needsConfirmation"; seq: number; inspection: InspectedSshHost; changed: boolean }
  | { kind: "confirmed"; seq: number; inspection: InspectedSshHost; changed: boolean };

export type HostTrustAction =
  | { type: "reset" }
  | { type: "check" }
  | { type: "inspected"; seq: number; inspection: InspectedSshHost }
  | { type: "checkFailed"; seq: number }
  | { type: "confirm"; confirmed: boolean }
  /** The key was remembered as this host's key. */
  | { type: "trusted"; seq: number };

export const initialHostTrust: HostTrustState = { kind: "unchecked", seq: 0 };

export function hostTrustReducer(state: HostTrustState, action: HostTrustAction): HostTrustState {
  if ("seq" in action && action.seq !== state.seq) return state;
  switch (action.type) {
    case "reset":
      return { kind: "unchecked", seq: state.seq + 1 };
    case "check":
      return { kind: "checking", seq: state.seq + 1 };
    case "inspected":
      if (state.kind !== "checking") return state;
      return action.inspection.status === "trusted"
        ? { kind: "trusted", seq: state.seq, inspection: action.inspection }
        : { kind: "needsConfirmation", seq: state.seq, inspection: action.inspection, changed: action.inspection.status === "changed" };
    case "checkFailed":
      return state.kind === "checking" ? { kind: "unchecked", seq: state.seq } : state;
    case "confirm":
      if (state.kind !== "needsConfirmation" && state.kind !== "confirmed") return state;
      return { ...state, kind: action.confirmed ? "confirmed" : "needsConfirmation" };
    case "trusted":
      return state.kind === "confirmed" || state.kind === "trusted"
        ? { kind: "trusted", seq: state.seq, inspection: { ...state.inspection, status: "trusted" } } : state;
  }
}
