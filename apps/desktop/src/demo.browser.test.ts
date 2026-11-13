import { afterEach, beforeEach, expect, it, vi } from "vitest";
import type { LocalStatusEvent } from "./types";

// No mock of @tauri-apps/api/core: a real Tauri Channel throws here, as in a plain browser under `pnpm dev`.
beforeEach(() => { vi.resetModules(); sessionStorage.clear(); });
afterEach(() => { delete window.__sirinDemo; delete window.__sirinPlatform; window.history.replaceState(null, "", "/"); vi.unstubAllGlobals(); });

it("streams demo status in a plain browser, with no Tauri bridge", async () => {
  expect("__TAURI_INTERNALS__" in window).toBe(false);
  sessionStorage.setItem("sirin.demo", "1");
  const { api } = await import("./api");
  const events: LocalStatusEvent[] = [];
  const stop = api.watchLocalStatus((event) => events.push(event));
  await vi.waitFor(() => expect(events[0]?.status?.state).toBe("connected"));
  stop();
  expect(events.every((event) => !event.stale)).toBe(true);
});

it("opens the demo from the address in a plain browser, and keeps it for the session", async () => {
  window.history.replaceState(null, "", "/?demo=1&platform=android&role=admin&future=1&keep=yes#home");
  const platform = await import("./platform");
  expect([platform.isDemo, platform.isAndroid, platform.browserDemo]).toEqual([true, true, true]);
  expect(sessionStorage.getItem("sirin.demo.role")).toBe("admin");
  expect(sessionStorage.getItem("sirin.demo.future")).toBe("1");
  expect(window.location.search).toBe("?keep=yes");
  expect(window.location.hash).toBe("#home");
});

it("never lets the address change the real app, or the platform outside the demo", async () => {
  window.history.replaceState(null, "", "/?platform=android");
  const platform = await import("./platform");
  expect([platform.isDemo, platform.isAndroid]).toEqual([false, false]);
  vi.resetModules(); sessionStorage.clear();
  window.history.replaceState(null, "", "/?demo=1");
  vi.stubGlobal("__TAURI_INTERNALS__", {});
  expect((await import("./platform")).isDemo).toBe(false);
  expect(sessionStorage.getItem("sirin.demo")).toBeNull();
});
