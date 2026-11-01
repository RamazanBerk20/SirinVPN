import { afterEach, beforeEach, expect, it, vi } from "vitest";
import type { LocalStatusEvent, ServerProfile } from "./types";

const native = vi.hoisted(() => ({ invoke: vi.fn() }));
vi.mock("@tauri-apps/api/core", () => ({ invoke: native.invoke, Channel: class { id = 1; onmessage = (_event: unknown) => {}; } }));

// Stands in for the webview's persistent storage, which the demo replaces for the page's life.
const saved = new Map<string, string>();
const browserStorage = { getItem: (key: string) => saved.get(key) ?? null, setItem: (key: string, value: string) => void saved.set(key, value),
  removeItem: (key: string) => void saved.delete(key), clear: () => saved.clear(), key: () => null, get length() { return saved.size; } };
beforeEach(() => {
  vi.resetModules(); sessionStorage.clear(); saved.clear();
  Object.defineProperty(window, "localStorage", { configurable: true, value: browserStorage });
});
afterEach(() => {
  delete window.__sirinDemo; delete window.__sirinPlatform;
  vi.unstubAllGlobals(); native.invoke.mockReset();
});

it("answers every demo command from sample data and never reaches the native bridge", async () => {
  sessionStorage.setItem("sirin.demo", "1");
  browserStorage.setItem("sirin.locale", "de");
  const { invoke, isDemo } = await import("./platform");
  expect(isDemo).toBe(true);
  expect(await invoke("client_platform")).toBe("desktop");
  const [profile] = await invoke<ServerProfile[]>("list_servers");
  expect(profile.name).toBe("My private VPS");
  await invoke("set_app_preferences", { preferences: { start_on_login: true } });
  await expect(invoke("export_device_backup", { serverId: profile.id })).rejects.toThrow("Unexpected visual fixture command");
  expect(native.invoke).not.toHaveBeenCalled();
  // The fixture took no part of the real bridge, and demo writes never reach the real browser storage.
  expect("__TAURI_INTERNALS__" in window).toBe(false);
  expect(localStorage.getItem("sirin-fixture-preferences")).toContain("start_on_login");
  expect(localStorage.getItem("sirin.locale")).toBeNull();
  expect(browserStorage.getItem("sirin-fixture-preferences")).toBeNull();
  expect(browserStorage.getItem("sirin.locale")).toBe("de");
});

it("keeps the Android demo off the native status watch", async () => {
  sessionStorage.setItem("sirin.demo", "1");
  vi.stubGlobal("navigator", { userAgent: "Mozilla/5.0 (Linux; Android 16)", onLine: true });
  const { api } = await import("./api");
  const { invoke, watchAndroidStatus } = await import("./platform");
  expect(await invoke("client_platform")).toBe("android");
  const events: LocalStatusEvent[] = [];
  const stop = api.watchLocalStatus((event) => events.push(event));
  const stopNative = watchAndroidStatus(() => events.push({ status: null, phase: "unknown", stale: true, sequence: 0, generation: 0 }));
  await vi.waitFor(() => expect(events[0]?.status?.state).toBe("connected"));
  stop(); stopNative();
  await new Promise((resolve) => setTimeout(resolve, 0));
  expect(events.every((event) => !event.stale)).toBe(true);
  expect(native.invoke).not.toHaveBeenCalled();
});

it("leaves the real app on the native bridge with no demo data", async () => {
  native.invoke.mockResolvedValue([]);
  const { invoke, isDemo } = await import("./platform");
  expect(isDemo).toBe(false);
  expect(await invoke("list_servers")).toEqual([]);
  expect(native.invoke).toHaveBeenCalledWith("list_servers", {});
  expect(window.__sirinDemo).toBeUndefined();
  expect(window.localStorage).toBe(browserStorage);
});

it("enters and leaves the demo only through a reload", async () => {
  const reload = vi.fn();
  vi.stubGlobal("location", { reload });
  const { setDemo } = await import("./platform");
  setDemo(true);
  expect(sessionStorage.getItem("sirin.demo")).toBe("1");
  setDemo(false);
  expect(sessionStorage.getItem("sirin.demo")).toBeNull();
  expect(reload).toHaveBeenCalledTimes(2);
});
