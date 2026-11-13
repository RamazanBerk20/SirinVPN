import { describe, expect, it } from "vitest";
import type { NetworkPreflight, ProvisionResult } from "../../types";
import { setupReducer, setupStep, type SetupEvent, type SetupState, type Verified } from "./setupMachine";

const preflight = { issues: [] } as unknown as NetworkPreflight;
const result = { profile: { id: "p" } } as unknown as ProvisionResult;
const bare: Verified = { target: "h:22", fingerprint: "SHA256:a", checked: null };
const checked = { ...bare, checked: { network: "n1", preflight } };
const error = { code: "unknown" as const, params: {}, detail: "boom" };

const states: Record<SetupState["kind"], SetupState> = {
  editing: { kind: "editing", verified: checked, error: null },
  probing: { kind: "probing", target: "h:22" },
  verifying: { kind: "verifying", verified: bare, error: null },
  checkingNetwork: { kind: "checkingNetwork", verified: bare, network: "n1", from: "verifying" },
  reviewed: { kind: "reviewed", verified: checked, error: null },
  installing: { kind: "installing", verified: checked },
  failed: { kind: "failed", verified: checked, error },
  done: { kind: "done", result },
};
const events: Record<SetupEvent["type"], SetupEvent> = {
  submit: { type: "submit", target: "h:22", network: "n1" },
  probed: { type: "probed", fingerprint: "SHA256:b" },
  probeFailed: { type: "probeFailed", error: "unreachable" },
  checkNetwork: { type: "checkNetwork", network: "n2" },
  checked: { type: "checked", preflight },
  checkFailed: { type: "checkFailed", error: "timed out" },
  install: { type: "install" },
  installed: { type: "installed", result },
  installFailed: { type: "installFailed", error },
  back: { type: "back" },
};
// Every (event, state) pair that changes state; all others must be ignored.
const accepted: Record<SetupEvent["type"], SetupState["kind"][]> = {
  submit: ["editing"], probed: ["probing"], probeFailed: ["probing"], checkNetwork: ["verifying", "reviewed"],
  checked: ["checkingNetwork"], checkFailed: ["checkingNetwork"], install: ["reviewed", "failed"], installed: ["installing"],
  installFailed: ["installing"], back: ["verifying", "reviewed", "failed"],
};

describe("setupReducer", () => {
  it("ignores every event a state does not accept", () => {
    for (const [type, event] of Object.entries(events) as [SetupEvent["type"], SetupEvent][])
      for (const [kind, state] of Object.entries(states) as [SetupState["kind"], SetupState][])
        if (!accepted[type].includes(kind)) expect(setupReducer(state, event), `${type} in ${kind}`).toBe(state);
  });

  it("probes a new target and reuses a verified one", () => {
    expect(setupReducer({ kind: "editing", verified: null, error: "old" }, events.submit)).toEqual({ kind: "probing", target: "h:22" });
    expect(setupReducer(states.editing, events.submit)).toEqual({ kind: "reviewed", verified: checked, error: null });
    // Same host, other ports: the key stays, the network check does not.
    expect(setupReducer(states.editing, { type: "submit", target: "h:22", network: "n2" })).toEqual({ kind: "verifying", verified: bare, error: null });
    expect(setupReducer(states.editing, { type: "submit", target: "other:22", network: "n1" })).toEqual({ kind: "probing", target: "other:22" });
    expect(setupReducer(states.probing, events.probed)).toEqual({ kind: "verifying", verified: { target: "h:22", fingerprint: "SHA256:b", checked: null }, error: null });
    expect(setupReducer(states.probing, events.probeFailed)).toEqual({ kind: "editing", verified: null, error: "unreachable" });
  });

  it("confirms the fingerprint only when the network check succeeds", () => {
    const checking = setupReducer(states.verifying, events.checkNetwork);
    expect(checking).toEqual({ kind: "checkingNetwork", verified: bare, network: "n2", from: "verifying" });
    expect(setupReducer(states.reviewed, events.checkNetwork)).toMatchObject({ kind: "checkingNetwork", from: "verifying" });
    expect(setupReducer(checking, events.checked)).toEqual({ kind: "reviewed", verified: { ...bare, checked: { network: "n2", preflight } }, error: null });
    expect(setupReducer(checking, events.checkFailed)).toEqual({ kind: "verifying", verified: bare, error: "timed out" });
  });

  it("checks a created server's pinned key from the form and returns there on failure", () => {
    const pinned = { type: "checkNetwork" as const, network: "n1", pinned: { target: "1.2.3.4:22", fingerprint: "SHA256:p" } };
    const checking = setupReducer({ kind: "editing", verified: null, error: null }, pinned);
    expect(checking).toEqual({ kind: "checkingNetwork", verified: { ...pinned.pinned, checked: null }, network: "n1", from: "editing" });
    expect(setupReducer(checking, events.checkFailed)).toEqual({ kind: "editing", verified: { ...pinned.pinned, checked: null }, error: "timed out" });
    expect(setupStep(checking)).toBe("details");
  });

  it("installs, fails with a typed error, retries and finishes", () => {
    const installing = setupReducer(states.reviewed, events.install);
    expect(installing).toEqual({ kind: "installing", verified: checked });
    expect(setupReducer(installing, events.installFailed)).toEqual({ kind: "failed", verified: checked, error });
    expect(setupReducer(states.failed, events.install)).toEqual(installing);
    expect(setupReducer(installing, events.installed)).toEqual({ kind: "done", result });
    // Back keeps the key and the check, so Continue needs no new probe.
    expect(setupReducer(states.failed, events.back)).toEqual({ kind: "editing", verified: checked, error: null });
  });

  it("names the step a parent sees", () => {
    expect(Object.fromEntries(Object.entries(states).map(([kind, state]) => [kind, setupStep(state)]))).toEqual({
      editing: "details", probing: "details", verifying: "fingerprint", checkingNetwork: "fingerprint", reviewed: "fingerprint",
      installing: "installing", failed: "failed", done: "success",
    });
  });
});
