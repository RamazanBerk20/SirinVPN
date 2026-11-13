import { describe, expect, it } from "vitest";
import type { ReleaseUpdateCandidate } from "../../types";
import { initialRelease, releaseBusy, releaseReducer as reduce, restartFor, type ReleaseAction, type ReleaseState } from "./releaseUpdateMachine";

const candidate = { release_version: "0.2.0", installer_kind: "debian" } as ReleaseUpdateCandidate;
const reviewing: ReleaseState = { kind: "reviewing", candidate, confirmed: false, busy: null, error: null };
const confirmed: ReleaseState = { ...reviewing, confirmed: true };
const installed: ReleaseState = { kind: "installed", candidate, restart: "available", busy: null, error: null };
const bound: ReleaseState = { ...installed, restart: "bound" };
const run = (state: ReleaseState, ...actions: ReleaseAction[]) => actions.reduce(reduce, state);

describe("release update machine", () => {
  it("checks, reviews, needs consent, installs", () => {
    const review = run(initialRelease, { type: "check" }, { type: "checked", candidate });
    expect(review).toEqual(reviewing);
    expect(reduce(review, { type: "install" })).toBe(review);
    const done = run(review, { type: "confirm", value: true }, { type: "install" }, { type: "installed", candidate });
    expect(done).toEqual(installed);
  });

  it("returns to the form or the review on failure, without consent", () => {
    expect(run(initialRelease, { type: "check" }, { type: "checkFailed", message: "x" })).toEqual({ ...initialRelease, error: { message: "x" } });
    expect(run(confirmed, { type: "install" }, { type: "installFailed", message: "y" })).toEqual({ ...reviewing, error: { message: "y" } });
  });

  it("derives the restart kind from the installed candidate", () => {
    expect(restartFor(candidate)).toBe("available");
    expect(restartFor({ ...candidate, installer_kind: "android" })).toBe("external");
    expect(restartFor({ ...candidate, installer_kind: "windows" })).toBe("external");
    expect(restartFor({ ...candidate, baseline_bound: true })).toBe("bound");
  });

  it("restarts only where a restart exists, and recovers from a failed one", () => {
    const restarting = reduce(installed, { type: "restart" });
    expect(restarting).toMatchObject({ busy: "restarting" });
    expect(releaseBusy(restarting)).toBe(true);
    expect(reduce(restarting, { type: "restartFailed", message: "m" })).toEqual({ ...installed, error: { message: "m" } });
    expect(reduce({ ...installed, restart: "external" }, { type: "restart" })).toEqual({ ...installed, restart: "external" });
    expect(reduce(initialRelease, { type: "restart" })).toBe(initialRelease);
    expect(reduce({ ...initialRelease, restored: true }, { type: "restart" })).toMatchObject({ kind: "form", busy: "restarting" });
  });

  it("checks for a newer release after binding, or keeps the bound result with a retry", () => {
    const checking = reduce(bound, { type: "checkAfterBinding" });
    expect(checking).toMatchObject({ busy: "checking" });
    expect(reduce(checking, { type: "check" })).toEqual({ kind: "checking" });
    expect(reduce(checking, { type: "discardFailed", error: { message: "d", retry: "checkAfterBinding" } }))
      .toEqual({ ...bound, error: { message: "d", retry: "checkAfterBinding" } });
    expect(reduce(installed, { type: "checkAfterBinding" })).toBe(installed);
  });

  it("disconnects and discards from the review, one at a time", () => {
    const disconnecting = reduce(confirmed, { type: "disconnect" });
    expect(reduce(disconnecting, { type: "discard" })).toBe(disconnecting);
    expect(reduce(disconnecting, { type: "disconnected" })).toEqual(confirmed);
    expect(reduce(disconnecting, { type: "disconnected", error: { message: "e", retry: "disconnect" } })).toMatchObject({ busy: null, error: { retry: "disconnect" } });
    const discarding = reduce(reviewing, { type: "discard" });
    expect(reduce(discarding, { type: "reset" })).toEqual(initialRelease);
    expect(reduce(discarding, { type: "discardFailed", error: { message: "f" } })).toEqual({ ...reviewing, error: { message: "f" } });
  });

  it("runs a rollback only from the form and remembers it was restored", () => {
    const recovering = reduce(initialRelease, { type: "recovery", running: true });
    expect(releaseBusy(recovering)).toBe(true);
    expect(reduce(recovering, { type: "check" })).toBe(recovering);
    expect(reduce(recovering, { type: "recovery", running: false, restored: true })).toEqual({ ...initialRelease, restored: true });
    expect(reduce(recovering, { type: "recovery", running: false })).toEqual(initialRelease);
    expect(reduce(reviewing, { type: "recovery", running: true })).toBe(reviewing);
  });

  it("closing keeps the reviewed candidate but drops consent; busy states can't close or reset", () => {
    expect(reduce(confirmed, { type: "closed" })).toEqual(reviewing);
    expect(reduce({ ...initialRelease, error: { message: "x" } }, { type: "closed" })).toEqual(initialRelease);
    const installing = reduce(confirmed, { type: "install" });
    expect(reduce(installing, { type: "closed" })).toBe(installing);
    expect(reduce(installing, { type: "reset" })).toBe(installing);
    expect(reduce(installed, { type: "reset" })).toEqual(initialRelease);
    expect(reduce({ kind: "checking" }, { type: "reset" })).toEqual({ kind: "checking" });
  });

  it("ignores actions that don't belong to the current state", () => {
    const stray: ReleaseAction[] = [{ type: "checked", candidate }, { type: "checkFailed", message: "" }, { type: "installed", candidate },
      { type: "installFailed", message: "" }, { type: "restartFailed", message: "" }, { type: "disconnected" }, { type: "discardFailed", error: { message: "" } }, { type: "confirm", value: true }];
    for (const action of stray) expect(reduce(initialRelease, action)).toBe(initialRelease);
    expect(reduce(installed, { type: "check" })).toBe(installed);
  });
});
