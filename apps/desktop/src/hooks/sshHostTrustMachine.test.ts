import { describe, expect, it } from "vitest";
import { hostTrustReducer, initialHostTrust, type HostTrustState, type InspectedSshHost } from "./sshHostTrustMachine";

const fp = (letter: string) => `SHA256:${letter.repeat(43)}`;
const inspection = (status: InspectedSshHost["status"], fingerprint = fp("A")): InspectedSshHost => ({ host: "vps.example", port: 22, fingerprint, status });
const checking: HostTrustState = { kind: "checking", seq: 1 };
const needs: HostTrustState = { kind: "needsConfirmation", seq: 1, inspection: inspection("unknown"), changed: false };
const confirmed: HostTrustState = { kind: "confirmed", seq: 1, inspection: inspection("unknown"), changed: false };
const trusted: HostTrustState = { kind: "trusted", seq: 1, inspection: inspection("trusted") };
const unchecked: HostTrustState = { kind: "unchecked", seq: 1 };
const all = [unchecked, checking, trusted, needs, confirmed];

describe("hostTrustReducer", () => {
  it("starts unchecked", () => expect(initialHostTrust).toEqual({ kind: "unchecked", seq: 0 }));

  it("reset and check start afresh from any state, dropping a confirmation", () => {
    for (const state of all) {
      expect(hostTrustReducer(state, { type: "reset" })).toEqual({ kind: "unchecked", seq: 2 });
      expect(hostTrustReducer(state, { type: "check" })).toEqual({ kind: "checking", seq: 2 });
    }
  });

  it("a trusted key needs no confirmation; an unknown or changed one does", () => {
    expect(hostTrustReducer(checking, { type: "inspected", seq: 1, inspection: inspection("trusted") }))
      .toEqual({ kind: "trusted", seq: 1, inspection: inspection("trusted") });
    expect(hostTrustReducer(checking, { type: "inspected", seq: 1, inspection: inspection("unknown") }))
      .toEqual({ kind: "needsConfirmation", seq: 1, inspection: inspection("unknown"), changed: false });
    expect(hostTrustReducer(checking, { type: "inspected", seq: 1, inspection: inspection("changed") }))
      .toEqual({ kind: "needsConfirmation", seq: 1, inspection: inspection("changed"), changed: true });
  });

  it("drops results for an older request or outside a check", () => {
    for (const state of all) {
      expect(hostTrustReducer(state, { type: "inspected", seq: 0, inspection: inspection("trusted") })).toBe(state);
      expect(hostTrustReducer(state, { type: "checkFailed", seq: 0 })).toBe(state);
      expect(hostTrustReducer(state, { type: "trusted", seq: 0 })).toBe(state);
      if (state.kind !== "checking") {
        expect(hostTrustReducer(state, { type: "inspected", seq: 1, inspection: inspection("trusted") })).toBe(state);
        expect(hostTrustReducer(state, { type: "checkFailed", seq: 1 })).toBe(state);
      }
    }
  });

  it("a failed check returns to unchecked", () => {
    expect(hostTrustReducer(checking, { type: "checkFailed", seq: 1 })).toEqual(unchecked);
  });

  it("confirms only a key that needs it, and can take the confirmation back", () => {
    expect(hostTrustReducer(needs, { type: "confirm", confirmed: true })).toEqual(confirmed);
    expect(hostTrustReducer(confirmed, { type: "confirm", confirmed: false })).toEqual(needs);
    expect(hostTrustReducer(needs, { type: "confirm", confirmed: false })).toEqual(needs);
    for (const state of [unchecked, checking, trusted]) expect(hostTrustReducer(state, { type: "confirm", confirmed: true })).toBe(state);
  });

  it("a new inspection of another key drops the confirmation of the old one", () => {
    const rechecking = hostTrustReducer(confirmed, { type: "check" });
    const next = hostTrustReducer(rechecking, { type: "inspected", seq: rechecking.seq, inspection: inspection("changed", fp("B")) });
    expect(next).toMatchObject({ kind: "needsConfirmation", changed: true, inspection: { fingerprint: fp("B") } });
  });

  it("remembering the key makes a confirmed or trusted key trusted, and nothing else", () => {
    expect(hostTrustReducer(confirmed, { type: "trusted", seq: 1 })).toEqual({ kind: "trusted", seq: 1, inspection: inspection("trusted") });
    expect(hostTrustReducer(trusted, { type: "trusted", seq: 1 })).toEqual(trusted);
    for (const state of [unchecked, checking, needs]) expect(hostTrustReducer(state, { type: "trusted", seq: 1 })).toBe(state);
  });
});
