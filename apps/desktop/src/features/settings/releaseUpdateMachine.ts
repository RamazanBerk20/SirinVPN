import type { ReleaseUpdateCandidate } from "../../types";

/** What a failed step offers: nothing (the visible primary action is the retry) or one named retry. */
export type ReleaseError = { message: string; retry?: "discard" | "checkAfterBinding" | "disconnect" };
/** After an install: restart here (Linux), the system takes over (Android, Windows), or the same version was bound. */
export type Restart = "available" | "external" | "bound";

export type ReleaseState =
  | { kind: "form"; busy: null | "recovering" | "restarting"; restored: boolean; error: ReleaseError | null }
  | { kind: "checking" }
  | { kind: "reviewing"; candidate: ReleaseUpdateCandidate; confirmed: boolean; busy: null | "disconnecting" | "discarding"; error: ReleaseError | null }
  | { kind: "installing"; candidate: ReleaseUpdateCandidate }
  | { kind: "installed"; candidate: ReleaseUpdateCandidate; restart: Restart; busy: null | "restarting" | "checking"; error: ReleaseError | null };

export type ReleaseAction =
  | { type: "check" }
  | { type: "checked"; candidate: ReleaseUpdateCandidate }
  | { type: "checkFailed"; message: string }
  | { type: "confirm"; value: boolean }
  | { type: "disconnect" }
  | { type: "disconnected"; error?: ReleaseError }
  | { type: "discard" }
  | { type: "discardFailed"; error: ReleaseError }
  | { type: "install" }
  | { type: "installed"; candidate: ReleaseUpdateCandidate }
  | { type: "installFailed"; message: string }
  | { type: "restart" }
  | { type: "restartFailed"; message: string }
  | { type: "checkAfterBinding" }
  | { type: "recovery"; running: boolean; restored?: boolean }
  /** The dialog closed without finishing; a reviewed candidate stays but needs fresh consent. */
  | { type: "closed" }
  | { type: "reset" };

export const initialRelease: Extract<ReleaseState, { kind: "form" }> = { kind: "form", busy: null, restored: false, error: null };

export function restartFor(candidate: ReleaseUpdateCandidate): Restart {
  if (candidate.baseline_bound) return "bound";
  return candidate.installer_kind === "android" || candidate.installer_kind === "windows" ? "external" : "available";
}

/** Whether anything is running, which locks closing and every other control. */
export function releaseBusy(state: ReleaseState): boolean {
  return state.kind === "checking" || state.kind === "installing" || ("busy" in state && state.busy !== null);
}

export function releaseReducer(state: ReleaseState, action: ReleaseAction): ReleaseState {
  switch (action.type) {
    case "check":
      return state.kind === "form" && state.busy === null || state.kind === "reviewing" && state.busy === null
        || state.kind === "installed" && state.busy === "checking" ? { kind: "checking" } : state;
    case "checked":
      return state.kind === "checking" ? { kind: "reviewing", candidate: action.candidate, confirmed: false, busy: null, error: null } : state;
    case "checkFailed":
      return state.kind === "checking" ? { ...initialRelease, error: { message: action.message } } : state;
    case "confirm":
      return state.kind === "reviewing" ? { ...state, confirmed: action.value } : state;
    case "disconnect":
      return state.kind === "reviewing" && state.busy === null ? { ...state, busy: "disconnecting", error: null } : state;
    case "disconnected":
      return state.kind === "reviewing" && state.busy === "disconnecting" ? { ...state, busy: null, error: action.error ?? null } : state;
    case "discard":
      return state.kind === "reviewing" && state.busy === null ? { ...state, busy: "discarding", error: null } : state;
    case "discardFailed":
      if (state.kind === "reviewing" && state.busy === "discarding") return { ...state, busy: null, error: action.error };
      if (state.kind === "installed" && state.busy === "checking") return { ...state, busy: null, error: action.error };
      return state;
    case "install":
      return state.kind === "reviewing" && state.confirmed && state.busy === null ? { kind: "installing", candidate: state.candidate } : state;
    case "installed":
      return state.kind === "installing" ? { kind: "installed", candidate: action.candidate, restart: restartFor(action.candidate), busy: null, error: null } : state;
    case "installFailed":
      return state.kind === "installing" ? { kind: "reviewing", candidate: state.candidate, confirmed: false, busy: null, error: { message: action.message } } : state;
    case "restart":
      if (state.kind === "installed" && state.restart === "available" && state.busy === null) return { ...state, busy: "restarting", error: null };
      // After a restored AppImage, the form offers the same restart.
      if (state.kind === "form" && state.restored && state.busy === null) return { ...state, busy: "restarting", error: null };
      return state;
    case "restartFailed":
      return (state.kind === "installed" || state.kind === "form") && state.busy === "restarting"
        ? { ...state, busy: null, error: { message: action.message } } : state;
    case "checkAfterBinding":
      return state.kind === "installed" && state.restart === "bound" && state.busy === null ? { ...state, busy: "checking", error: null } : state;
    case "recovery":
      if (state.kind !== "form") return state;
      if (action.running) return state.busy === null ? { ...state, busy: "recovering" } : state;
      return state.busy === "recovering" ? { ...state, busy: null, restored: state.restored || Boolean(action.restored) } : state;
    case "closed":
      if (releaseBusy(state)) return state;
      return state.kind === "reviewing" ? { ...state, confirmed: false, error: null } : state.kind === "form" ? { ...state, error: null } : state;
    case "reset":
      return releaseBusy(state) && !(state.kind === "reviewing" && state.busy === "discarding")
        && !(state.kind === "installed" && state.busy === "checking") ? state : initialRelease;
  }
}
