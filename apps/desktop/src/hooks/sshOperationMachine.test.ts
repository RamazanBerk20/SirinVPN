import { describe, expect, it } from "vitest";
import { operationView, sshOperationReducer, type SshOperationAction, type SshOperationState } from "./sshOperationMachine";

type S = SshOperationState<string>;
const states: S[] = [
  { kind: "form" }, { kind: "verifyingHost" }, { kind: "confirmHost" }, { kind: "review" },
  { kind: "running", phase: 1 }, { kind: "succeeded", result: "ok" },
  { kind: "failed", error: "e", returnTo: "form" }, { kind: "failed", error: "e", returnTo: "review" },
];
const step = (state: S, action: SshOperationAction<string>) => sshOperationReducer(state, action);
const label = (state: S) => state.kind === "failed" ? `failed:${state.returnTo}` : state.kind;

// Every state × action pair, written out as the kind it leads to.
const table: Record<string, Record<string, string>> = {
  reset: { form: "form", verifyingHost: "form", confirmHost: "form", review: "form", running: "form", succeeded: "form", "failed:form": "form", "failed:review": "form" },
  verify: { form: "verifyingHost", verifyingHost: "verifyingHost", confirmHost: "confirmHost", review: "review", running: "running", succeeded: "succeeded", "failed:form": "verifyingHost", "failed:review": "verifyingHost" },
  confirmHost: { form: "form", verifyingHost: "confirmHost", confirmHost: "confirmHost", review: "review", running: "running", succeeded: "succeeded", "failed:form": "failed:form", "failed:review": "failed:review" },
  review: { form: "form", verifyingHost: "review", confirmHost: "review", review: "review", running: "running", succeeded: "succeeded", "failed:form": "failed:form", "failed:review": "failed:review" },
  back: { form: "form", verifyingHost: "form", confirmHost: "form", review: "form", running: "running", succeeded: "form", "failed:form": "form", "failed:review": "form" },
  run: { form: "form", verifyingHost: "running", confirmHost: "running", review: "running", running: "running", succeeded: "succeeded", "failed:form": "failed:form", "failed:review": "running" },
  phase: { form: "form", verifyingHost: "verifyingHost", confirmHost: "confirmHost", review: "review", running: "running", succeeded: "succeeded", "failed:form": "failed:form", "failed:review": "failed:review" },
  succeeded: { form: "form", verifyingHost: "verifyingHost", confirmHost: "confirmHost", review: "review", running: "succeeded", succeeded: "succeeded", "failed:form": "failed:form", "failed:review": "failed:review" },
  failed: { form: "form", verifyingHost: "failed:form", confirmHost: "confirmHost", review: "review", running: "failed:form", succeeded: "succeeded", "failed:form": "failed:form", "failed:review": "failed:review" },
};
const actions: Record<string, SshOperationAction<string>> = {
  reset: { type: "reset" }, verify: { type: "verify" }, confirmHost: { type: "confirmHost" }, review: { type: "review" }, back: { type: "back" },
  run: { type: "run" }, phase: { type: "phase", phase: 2 }, succeeded: { type: "succeeded", result: "r" }, failed: { type: "failed", error: "x" },
};

describe("sshOperationReducer", () => {
  for (const [name, row] of Object.entries(table))
    for (const state of states)
      it(`${name} from ${label(state)} → ${row[label(state)]}`, () => {
        expect(label(step(state, actions[name]))).toBe(row[label(state)]);
      });

  it("starts running at phase 0, records later phases and the result", () => {
    let state = step({ kind: "review" }, { type: "run" });
    expect(state).toEqual({ kind: "running", phase: 0 });
    state = step(state, { type: "phase", phase: 2 });
    expect(state).toEqual({ kind: "running", phase: 2 });
    expect(step(state, { type: "succeeded", result: "r" })).toEqual({ kind: "succeeded", result: "r" });
  });

  it("keeps the error and where the failure returns to, so success and error never coexist", () => {
    expect(step({ kind: "running", phase: 1 }, { type: "failed", error: "x", returnTo: "review" })).toEqual({ kind: "failed", error: "x", returnTo: "review" });
    const failed = step({ kind: "running", phase: 1 }, { type: "failed", error: "x" });
    expect(step(failed, { type: "succeeded", result: "r" })).toBe(failed);
    const done: S = { kind: "succeeded", result: "r" };
    expect(step(done, { type: "failed", error: "x" })).toBe(done);
  });
});

describe("operationView", () => {
  it("shows the form while checking the host and a failure where it returns to", () => {
    expect(states.map(operationView)).toEqual(["form", "form", "confirmHost", "review", "running", "succeeded", "form", "review"]);
  });
});
