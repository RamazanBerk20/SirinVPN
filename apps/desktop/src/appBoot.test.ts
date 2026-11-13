import { describe, expect, it } from "vitest";
import { bootPlatform, bootReducer, initialBoot, type BootAction, type BootState } from "./appBoot";
import type { ServerProfile } from "./types";

const server = (id: string) => ({ id, name: id }) as ServerProfile;
const a = server("a"), b = server("b");
const detected: BootState = { kind: "detecting", platform: "desktop" };
const empty: BootState = { kind: "empty", platform: "desktop" };
const storeFailed: BootState = { kind: "storeFailed", platform: "desktop" };
const ready: BootState = { kind: "ready", platform: "desktop", servers: [a, b], selectedId: "b", notice: null };
const states: BootState[] = [initialBoot, detected, { kind: "platformFailed" }, storeFailed, empty, ready];
const actions: BootAction[] = [
  { type: "detect" }, { type: "platformDetected", platform: "android" }, { type: "platformFailed" }, { type: "reload" },
  { type: "serversLoaded", servers: [a] }, { type: "serversLoaded", servers: [] }, { type: "serversFailed" },
  { type: "serversChanged", update: [b] }, { type: "select", id: "a" }, { type: "notice", notice: "trayServer" },
];

describe("bootReducer", () => {
  it("never yields a platform-less state other than detecting or platformFailed", () => {
    for (const state of states) for (const action of actions) {
      const next = bootReducer(state, action);
      if (next.kind !== "detecting" && next.kind !== "platformFailed") expect(bootPlatform(next)).not.toBeNull();
      if (next.kind === "ready") {
        expect(next.servers.length).toBeGreaterThan(0);
        expect(next.servers.some(item => item.id === next.selectedId)).toBe(true);
      }
    }
  });

  it("detects the platform, then reads the servers", () => {
    expect(bootReducer(initialBoot, { type: "platformDetected", platform: "desktop" })).toEqual(detected);
    expect(bootReducer(initialBoot, { type: "platformFailed" })).toEqual({ kind: "platformFailed" });
    // Servers can't load before the platform is known.
    expect(bootReducer(initialBoot, { type: "serversLoaded", servers: [a] })).toBe(initialBoot);
    expect(bootReducer(detected, { type: "serversLoaded", servers: [] })).toEqual(empty);
    expect(bootReducer(detected, { type: "serversLoaded", servers: [a, b] })).toEqual({ ...ready, selectedId: "a" });
    expect(bootReducer(detected, { type: "serversFailed" })).toEqual(storeFailed);
    expect(bootReducer(empty, { type: "serversFailed" })).toEqual(storeFailed);
    expect(bootReducer(storeFailed, { type: "reload" })).toEqual(detected);
    expect(bootReducer(ready, { type: "detect" })).toEqual(initialBoot);
  });

  it("keeps the selection across reloads and selects a just-added server", () => {
    expect(bootReducer(ready, { type: "serversLoaded", servers: [a, b] })).toEqual(ready);
    expect(bootReducer(ready, { type: "serversLoaded", servers: [a] })).toMatchObject({ selectedId: "a" });
    expect(bootReducer(empty, { type: "serversLoaded", servers: [a, b], select: "b" })).toEqual(ready);
    expect(bootReducer(ready, { type: "serversLoaded", servers: [] })).toEqual(empty);
  });

  it("shows a failed reload as a notice over the list it still has, cleared by the next read", () => {
    const failed = bootReducer(ready, { type: "serversFailed" });
    expect(failed).toEqual({ ...ready, notice: "profiles" });
    expect(bootReducer(failed, { type: "serversLoaded", servers: [a, b] })).toEqual(ready);
    expect(bootReducer(ready, { type: "notice", notice: "trayServer" })).toMatchObject({ notice: "trayServer" });
    expect(bootReducer(empty, { type: "notice", notice: "trayServer" })).toBe(empty);
  });

  it("selects only listed servers and applies in-place list updates", () => {
    expect(bootReducer(ready, { type: "select", id: "a" })).toMatchObject({ selectedId: "a" });
    expect(bootReducer(ready, { type: "select", id: "missing" })).toBe(ready);
    expect(bootReducer(ready, { type: "serversChanged", update: list => list.map(item => ({ ...item, name: "x" })) }))
      .toMatchObject({ servers: [{ name: "x" }, { name: "x" }], selectedId: "b" });
    expect(bootReducer(empty, { type: "serversChanged", update: [a] })).toBe(empty);
  });
});
