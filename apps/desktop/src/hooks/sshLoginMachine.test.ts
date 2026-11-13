import { describe, expect, it } from "vitest";
import type { SavedSshLogin } from "../types";
import { initialSshLogin, newDraft, sshLoginReducer, type SshLoginAction, type SshLoginState } from "./sshLoginMachine";

const login: SavedSshLogin = { username: "admin", ssh_port: 2222, authentication: "private_key", private_key_path: "/k" };
const other: SavedSshLogin = { username: "ops", ssh_port: 22, authentication: "agent", private_key_path: null };
const typed = { ...newDraft(), password: "pw", keyPassphrase: "kp", sudoPassword: "sp" };
const fromLogin = { ...newDraft(), username: "admin", port: "2222", auth: "private_key" as const, keyPath: "/k" };
const host = "vps.example";
const idle: SshLoginState = initialSshLogin;
const looking: SshLoginState = { kind: "looking", host, seq: 1, slow: false, draft: typed };
const saved: SshLoginState = { kind: "saved", host, seq: 1, login, draft: fromLogin, error: null };
const editingNew: SshLoginState = { kind: "editing", host, seq: 1, login: null, draft: typed, error: null };
const editingSaved: SshLoginState = { kind: "editing", host, seq: 1, login, draft: typed, error: null };
const forgetting: SshLoginState = { kind: "forgetting", host, seq: 1, login, from: "saved", draft: fromLogin };
const failed: SshLoginState = { kind: "lookupFailed", host, seq: 1, message: "locked", draft: typed };
const all = [idle, looking, saved, editingNew, editingSaved, forgetting, failed];
const run = (state: SshLoginState, ...actions: SshLoginAction[]) => actions.reduce(sshLoginReducer, state);

describe("sshLoginReducer", () => {
  it("a destination starts a new lookup with a fresh draft; none returns to idle", () => {
    for (const state of all) {
      const seq = state.kind === "idle" ? 0 : state.seq;
      expect(run(state, { type: "destination", host: "new.example" })).toEqual({ kind: "looking", host: "new.example", seq: seq + 1, slow: false, draft: newDraft() });
      expect(run(state, { type: "destination", host: null })).toEqual(idle);
    }
  });

  it("retry reads again for the same destination, keeping what was typed", () => {
    expect(run(idle, { type: "retry" })).toBe(idle);
    for (const state of all.filter(s => s.kind !== "idle"))
      expect(run(state, { type: "retry" })).toEqual({ kind: "looking", host, seq: 2, slow: false, draft: state.draft });
  });

  it("announces only a slow lookup", () => {
    expect(run(looking, { type: "slow", seq: 1 })).toEqual({ ...looking, slow: true });
    for (const state of all.filter(s => s.kind !== "looking")) expect(run(state, { type: "slow", seq: 1 })).toBe(state);
  });

  it("a found login is used without its secrets; none means entering one", () => {
    expect(run(looking, { type: "found", seq: 1, login })).toEqual(saved);
    expect(run(looking, { type: "found", seq: 1, login: null })).toEqual(editingNew);
    for (const state of all.filter(s => s.kind !== "looking")) expect(run(state, { type: "found", seq: 1, login })).toBe(state);
  });

  it("a failed lookup still lets the user enter a login", () => {
    expect(run(looking, { type: "lookupFailed", seq: 1, message: "locked" })).toEqual(failed);
    for (const state of all.filter(s => s.kind !== "looking")) expect(run(state, { type: "lookupFailed", seq: 1, message: "x" })).toBe(state);
  });

  it("drops every result of an older lookup, forget or save, and any in idle", () => {
    const stale: SshLoginAction[] = [
      { type: "slow", seq: 0 }, { type: "found", seq: 0, login }, { type: "lookupFailed", seq: 0, message: "x" },
      { type: "forgotten", seq: 0 }, { type: "forgetFailed", seq: 0, message: "x" }, { type: "committed", seq: 0, login },
    ];
    for (const state of all) for (const action of stale) expect(run(state, action)).toBe(state);
    expect(run(idle, { type: "found", seq: 0, login })).toBe(idle);
  });

  it("change and clearSecrets edit the draft in every state", () => {
    for (const state of all) {
      expect(run(state, { type: "change", patch: { username: "u" } }).draft.username).toBe("u");
      expect(run(state, { type: "change", patch: { username: "u" } }).kind).toBe(state.kind);
      expect(run(state, { type: "clearSecrets" }).draft).toMatchObject({ password: "", keyPassphrase: "", sudoPassword: "" });
    }
  });

  it("edit leaves a saved login for typing, and reuse goes back to it", () => {
    expect(run(saved, { type: "edit" })).toEqual({ kind: "editing", host, seq: 1, login, draft: fromLogin, error: null });
    expect(run(editingSaved, { type: "reuse" })).toEqual({ ...saved, draft: { ...fromLogin, remember: typed.remember } });
    for (const state of all.filter(s => s.kind !== "saved")) expect(run(state, { type: "edit" })).toBe(state);
    for (const state of all.filter(s => s !== editingSaved)) expect(run(state, { type: "reuse" })).toBe(state);
  });

  it("forget is offered for a saved login, an edited one, and an unreadable keyring", () => {
    expect(run(saved, { type: "forget" })).toEqual({ ...forgetting, from: "saved" });
    expect(run(editingSaved, { type: "forget" })).toEqual({ kind: "forgetting", host, seq: 1, login, from: "editing", draft: typed });
    expect(run(failed, { type: "forget" })).toEqual({ kind: "forgetting", host, seq: 1, login: null, from: "lookupFailed", draft: typed });
    for (const state of [idle, looking, editingNew, forgetting]) expect(run(state, { type: "forget" })).toBe(state);
  });

  it("a forgotten login leaves an empty login to enter", () => {
    expect(run(forgetting, { type: "forgotten", seq: 1 })).toEqual({ kind: "editing", host, seq: 1, login: null, draft: fromLogin, error: null });
    for (const state of all.filter(s => s.kind !== "forgetting")) expect(run(state, { type: "forgotten", seq: 1 })).toBe(state);
  });

  it("a failed forget returns to where it started, with the error", () => {
    expect(run(saved, { type: "forget" }, { type: "forgetFailed", seq: 1, message: "x" })).toEqual({ ...saved, error: "x" });
    expect(run(editingSaved, { type: "forget" }, { type: "forgetFailed", seq: 1, message: "x" })).toEqual({ ...editingSaved, error: "x" });
    expect(run(failed, { type: "forget" }, { type: "forgetFailed", seq: 1, message: "x" })).toEqual({ ...failed, message: "x" });
    for (const state of all.filter(s => s.kind !== "forgetting")) expect(run(state, { type: "forgetFailed", seq: 1, message: "x" })).toBe(state);
  });

  it("a login saved after it worked becomes the saved login; not while looking or forgetting", () => {
    for (const state of [saved, editingNew, editingSaved, failed])
      expect(run(state, { type: "committed", seq: 1, login: other })).toEqual({ kind: "saved", host, seq: 1, login: other, error: null,
        draft: { ...newDraft(), remember: state.draft.remember, username: "ops", port: "22", auth: "agent", keyPath: "" } });
    for (const state of [idle, looking, forgetting]) expect(run(state, { type: "committed", seq: 1, login: other })).toBe(state);
  });
});
