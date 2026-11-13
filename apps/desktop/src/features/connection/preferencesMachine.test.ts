import { describe, expect, it } from "vitest";
import { defaultConnectionPreferences as defaults, type ConnectionPreferences } from "./connectionPreferences";
import { preferencesReducer as reduce, type PreferencesState } from "./preferencesMachine";

const value: ConnectionPreferences = { ...defaults, routing: { mode: "selected_routes", included_routes: ["10.0.0.0/8"], allow_lan: false } };
const loading: PreferencesState = { state: "loading", request: 1 };
const editing = reduce(loading, { type: "loaded", request: 1, value });
const saving = reduce(editing, { type: "save", request: 2, only: "all" });

describe("preferencesReducer", () => {
  it("loads into a clean editor, or fails with a message", () => {
    expect(editing).toEqual({ state: "editing", saved: value, draft: value, routesText: "10.0.0.0/8" });
    expect(reduce(loading, { type: "failed", request: 1, message: "x" })).toEqual({ state: "loadFailed", request: 1, message: "x" });
  });
  it("drops answers for a replaced load", () => {
    const again = reduce(editing, { type: "load", request: 3 });
    expect(again).toEqual({ state: "loading", request: 3 });
    expect(reduce(again, { type: "loaded", request: 1, value })).toBe(again);
    expect(reduce(again, { type: "failed", request: 1, message: "x" })).toBe(again);
    expect(reduce(saving, { type: "loaded", request: 2, value })).toBe(saving);
  });
  it("ignores edits, saves and discards before the preferences are loaded", () => {
    const failed: PreferencesState = { state: "loadFailed", request: 1, message: "x" };
    for (const state of [loading, failed]) {
      expect(reduce(state, { type: "edit", routesText: "a" })).toBe(state);
      expect(reduce(state, { type: "save", request: 4, only: "all" })).toBe(state);
      expect(reduce(state, { type: "discard" })).toBe(state);
    }
  });
  it("edits the draft and routes text, and discards back to saved", () => {
    const edited = reduce(reduce(editing, { type: "edit", draft: (draft) => ({ ...draft, manual_mtu: 1300 }) }), { type: "edit", routesText: "1.2.3.0/24" });
    expect(edited).toMatchObject({ state: "editing", draft: { manual_mtu: 1300 }, routesText: "1.2.3.0/24", saved: value });
    expect(reduce(edited, { type: "discard" })).toEqual(editing);
  });
  it("saves: saving → editing with the answer, or saveFailed keeping the draft", () => {
    expect(saving).toMatchObject({ state: "saving", request: 2, only: "all" });
    expect(reduce(saving, { type: "save", request: 5, only: "all" })).toBe(saving);
    expect(reduce(saving, { type: "discard" })).toBe(saving);
    const answer = { ...value, manual_mtu: 1400 };
    expect(reduce(saving, { type: "saved", request: 2, value: answer })).toEqual({ state: "editing", saved: answer, draft: answer, routesText: "10.0.0.0/8" });
    expect(reduce(saving, { type: "saved", request: 9, value: answer })).toBe(saving);
    const failed = reduce(saving, { type: "failed", request: 2, message: "no" });
    expect(failed).toEqual({ state: "saveFailed", message: "no", saved: value, draft: value, routesText: "10.0.0.0/8" });
    expect(reduce(failed, { type: "saved", request: 2, value })).toBe(failed);
    // A failed save can be retried, or edited back into a plain editor.
    expect(reduce(failed, { type: "save", request: 6, only: "all" }).state).toBe("saving");
    expect(reduce(failed, { type: "edit", routesText: "x" }).state).toBe("editing");
    expect(reduce(failed, { type: "discard" })).toEqual(editing);
  });
  it("an edit during a save stays saving", () => {
    expect(reduce(saving, { type: "edit", routesText: "x" })).toMatchObject({ state: "saving", routesText: "x" });
  });
  it("saving only the reconnect switch keeps the rest of the draft", () => {
    const draft = reduce(editing, { type: "edit", draft: (d) => ({ ...d, transport: "direct_udp" }) });
    const switching = reduce(draft, { type: "save", request: 7, only: "reconnect" });
    const answer = { ...value, policy: { ...value.policy, automatic_reconnect: true } };
    const done = reduce(switching, { type: "saved", request: 7, value: answer });
    expect(done).toMatchObject({ state: "editing", saved: answer, draft: { transport: "direct_udp", policy: { automatic_reconnect: true } } });
  });
});
