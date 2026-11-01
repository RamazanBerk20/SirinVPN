import { afterEach, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({ invoke: vi.fn(async () => null), android: false }));
vi.mock("../../platform", () => ({ get isAndroid() { return mocks.android; }, invoke: mocks.invoke }));
import { followTheme, resolveTheme } from "./theme";

function systemTheme(light: boolean) {
  const listeners = new Set<() => void>();
  const query = {
    matches: light,
    addEventListener: (_: string, listener: () => void) => listeners.add(listener),
    removeEventListener: (_: string, listener: () => void) => listeners.delete(listener),
  };
  window.matchMedia = vi.fn(() => query) as unknown as typeof window.matchMedia;
  return { listeners, change(next: boolean) { query.matches = next; listeners.forEach(listener => listener()); } };
}
afterEach(() => {
  Reflect.deleteProperty(window, "matchMedia");
  delete document.documentElement.dataset.theme;
  mocks.android = false;
  mocks.invoke.mockClear();
});

it("lets an explicit choice override the system setting", () => {
  expect(resolveTheme("light", false)).toBe("light");
  expect(resolveTheme("dark", true)).toBe("dark");
  expect(resolveTheme("system", true)).toBe("light");
  expect(resolveTheme("system", false)).toBe("dark");
  // Before preferences load the system decides.
  expect(resolveTheme(undefined, true)).toBe("light");
});

it("follows system changes until the preference is replaced", () => {
  const system = systemTheme(false);
  const stop = followTheme("system");
  expect(document.documentElement.dataset.theme).toBe("dark");
  system.change(true);
  expect(document.documentElement.dataset.theme).toBe("light");
  stop();
  expect(system.listeners.size).toBe(0);
  system.change(false);
  expect(document.documentElement.dataset.theme).toBe("light");
});

it("keeps an explicit choice when the system setting changes", () => {
  const system = systemTheme(true);
  followTheme("dark");
  system.change(false);
  system.change(true);
  expect(document.documentElement.dataset.theme).toBe("dark");
});

it("stays dark without a system preference to read", () => {
  followTheme("system")();
  expect(document.documentElement.dataset.theme).toBe("dark");
});

it("tells Android which system bar style matches the theme", () => {
  mocks.android = true;
  const system = systemTheme(false);
  followTheme("system");
  system.change(true);
  expect(mocks.invoke.mock.calls).toEqual([["android_system_bars", { light: false }], ["android_system_bars", { light: true }]]);
});
