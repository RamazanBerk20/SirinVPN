/**
 * One SSH maintenance task on a VPS (repair, VPS update, backup, restore, uninstall):
 * form → verifyingHost → (confirmHost →) (review →) running{phase} → succeeded{result}.
 * A failure shows its error on the step named by `returnTo` (the form unless the caller says
 * otherwise); success and error are never shown together.
 */
export type SshOperationStep = "form" | "confirmHost" | "review";

export type SshOperationState<R> =
  | { kind: "form" }
  | { kind: "verifyingHost" }
  | { kind: "confirmHost" }
  | { kind: "review" }
  | { kind: "running"; phase: number }
  | { kind: "succeeded"; result: R }
  | { kind: "failed"; error: string; returnTo: SshOperationStep };

export type SshOperationAction<R> =
  | { type: "reset" }
  | { type: "verify" }
  | { type: "confirmHost" }
  | { type: "review" }
  | { type: "back" }
  | { type: "run" }
  | { type: "phase"; phase: number }
  | { type: "succeeded"; result: R }
  | { type: "failed"; error: string; returnTo?: SshOperationStep };

export const initialSshOperation = { kind: "form" } as const;

export function sshOperationReducer<R>(state: SshOperationState<R>, action: SshOperationAction<R>): SshOperationState<R> {
  switch (action.type) {
    case "reset":
      return { kind: "form" };
    case "verify":
      return state.kind === "form" || state.kind === "failed" ? { kind: "verifyingHost" } : state;
    case "confirmHost":
      return state.kind === "verifyingHost" ? { kind: "confirmHost" } : state;
    case "review":
      return state.kind === "verifyingHost" || state.kind === "confirmHost" ? { kind: "review" } : state;
    case "back":
      // A running task can't be left.
      return state.kind === "running" ? state : { kind: "form" };
    case "run":
      return state.kind === "verifyingHost" || state.kind === "confirmHost" || state.kind === "review" ||
        state.kind === "failed" && state.returnTo !== "form" ? { kind: "running", phase: 0 } : state;
    case "phase":
      return state.kind === "running" ? { kind: "running", phase: action.phase } : state;
    case "succeeded":
      return state.kind === "running" ? { kind: "succeeded", result: action.result } : state;
    case "failed":
      return state.kind === "running" || state.kind === "verifyingHost"
        ? { kind: "failed", error: action.error, returnTo: action.returnTo ?? "form" } : state;
  }
}

/** The step a dialog renders: the form also shows while the host is checked; a failure shows where it returns to. */
export type SshOperationView = "form" | "confirmHost" | "review" | "running" | "succeeded";
export function operationView(state: SshOperationState<unknown>): SshOperationView {
  return state.kind === "verifyingHost" ? "form" : state.kind === "failed" ? state.returnTo : state.kind;
}
