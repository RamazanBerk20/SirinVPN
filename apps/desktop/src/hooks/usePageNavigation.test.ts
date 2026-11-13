import { afterEach, expect, it } from "vitest";
import { act, renderHook } from "@testing-library/react";
import { registerNavigationGuard } from "../lib/navigationGuard";
import { usePageNavigation } from "./usePageNavigation";

afterEach(() => window.history.replaceState(null, "", "#home"));

it("keeps the settings category in the URL, so Back returns to the previous tab", () => {
  const { result } = renderHook(() => usePageNavigation());
  act(() => result.current[1]("settings", "network"));
  act(() => result.current[1]("settings", "recovery"));
  expect(window.location.hash).toBe("#settings/recovery");
  act(() => { window.history.back(); });
  return new Promise<void>(resolve => window.addEventListener("popstate", () => setTimeout(() => {
    expect(result.current[0]).toBe("settings");
    expect(result.current[2]).toBe("network");
    resolve();
  }), { once: true }));
});

it("lets a navigation guard refuse a browser Back, keeping the shown page", () => {
  const { result } = renderHook(() => usePageNavigation());
  act(() => result.current[1]("servers"));
  const release = registerNavigationGuard(() => false);
  window.history.replaceState(window.history.state, "", "#home");
  act(() => { window.dispatchEvent(new PopStateEvent("popstate")); });
  release();
  expect(result.current[0]).toBe("servers");
  expect(window.location.hash).toBe("#servers");
});
