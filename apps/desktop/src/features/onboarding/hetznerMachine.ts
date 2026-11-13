import type { CreatedHetznerServer, HetznerReady } from "../../types";

/**
 * The Hetzner wizard. Once a create request may have reached Hetzner, the flow never offers Create
 * again until the Owner settles whether that server exists ("uncertain").
 */
export type HetznerState =
  | { kind: "plan" }
  | { kind: "loadingPlans" }
  | { kind: "creating" }
  /** Hetzner may have created `name`. `found` is set once a check found it; `checked` once a check found nothing. */
  | { kind: "uncertain"; name: string; checking: boolean; checked: boolean; found: CreatedHetznerServer | null }
  | { kind: "waiting"; created: CreatedHetznerServer }
  | { kind: "failed"; created: CreatedHetznerServer; deleting: boolean }
  | { kind: "install"; created: CreatedHetznerServer; ready: HetznerReady; deleting: boolean }
  | { kind: "kept"; created: CreatedHetznerServer }
  | { kind: "deleted"; created: CreatedHetznerServer };

export type HetznerEvent =
  | { type: "loadPlans" }
  | { type: "plansDone" }
  | { type: "create" }
  | { type: "createFailed" }
  | { type: "createUncertain"; name: string }
  | { type: "check" }
  | { type: "checked"; found: CreatedHetznerServer | null }
  | { type: "checkFailed" }
  /** The Owner confirmed the uncertain server does not exist. */
  | { type: "absent" }
  /** Waits for a created, adopted or not-yet-ready server. */
  | { type: "wait"; created: CreatedHetznerServer }
  | { type: "ready"; ready: HetznerReady }
  | { type: "waitFailed" }
  | { type: "keep" }
  | { type: "delete" }
  | { type: "deleted" }
  | { type: "deleteFailed" }
  | { type: "startOver" };

export const initialHetzner: HetznerState = { kind: "plan" };

export function hetznerReducer(state: HetznerState, event: HetznerEvent): HetznerState {
  switch (event.type) {
    case "loadPlans": return state.kind === "plan" ? { kind: "loadingPlans" } : state;
    case "plansDone": return state.kind === "loadingPlans" ? { kind: "plan" } : state;
    case "create": return state.kind === "plan" ? { kind: "creating" } : state;
    case "createFailed": return state.kind === "creating" ? { kind: "plan" } : state;
    case "createUncertain": return state.kind === "creating" ? { kind: "uncertain", name: event.name, checking: false, checked: false, found: null } : state;
    case "check": return state.kind === "uncertain" && !state.checking ? { ...state, checking: true } : state;
    case "checked": return state.kind === "uncertain" && state.checking ? { ...state, checking: false, checked: event.found === null, found: event.found } : state;
    case "checkFailed": return state.kind === "uncertain" && state.checking ? { ...state, checking: false } : state;
    case "absent": return state.kind === "uncertain" && !state.checking && !state.found ? { kind: "plan" } : state;
    case "wait":
      return state.kind === "creating" || state.kind === "failed" && !state.deleting || state.kind === "uncertain" && state.found !== null
        ? { kind: "waiting", created: event.created } : state;
    case "ready": return state.kind === "waiting" ? { kind: "install", created: state.created, ready: event.ready, deleting: false } : state;
    case "waitFailed": return state.kind === "waiting" ? { kind: "failed", created: state.created, deleting: false } : state;
    case "keep": return state.kind === "failed" && !state.deleting ? { kind: "kept", created: state.created } : state;
    case "delete": return (state.kind === "failed" || state.kind === "install") && !state.deleting ? { ...state, deleting: true } : state;
    case "deleted": return (state.kind === "failed" || state.kind === "install") && state.deleting ? { kind: "deleted", created: state.created } : state;
    case "deleteFailed": return (state.kind === "failed" || state.kind === "install") && state.deleting ? { ...state, deleting: false } : state;
    case "startOver": return state.kind === "deleted" ? { kind: "plan" } : state;
  }
}

/** The server exists or may exist and bills the Owner: leaving needs a decision. */
export function hetznerUnresolved(state: HetznerState): boolean {
  return !["plan", "loadingPlans", "kept", "deleted"].includes(state.kind);
}
