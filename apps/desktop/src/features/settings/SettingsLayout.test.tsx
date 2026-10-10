import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { SettingsLayout } from "./SettingsLayout";

const scrollBy = vi.hoisted(() => vi.fn());
vi.mock("../../lib/scrolling", () => ({ pageScrollPort: () => ({ scrollBy }) }));
vi.mock("./PreferencesProvider", () => ({ usePreferences: () => ({ snapshot: { preferences: { animations: false } } }) }));

beforeEach(() => {
  vi.stubGlobal("requestAnimationFrame", (callback: FrameRequestCallback) => { callback(0); return 1; });
});
afterEach(() => { cleanup(); vi.restoreAllMocks(); vi.unstubAllGlobals(); scrollBy.mockClear(); });

function settings() {
  render(<SettingsLayout category="general" onChange={vi.fn()}>
    <p>Some settings</p><button>Change preference</button>
  </SettingsLayout>);
  vi.spyOn(screen.getByRole("tablist"), "getBoundingClientRect").mockReturnValue({ bottom: 60 } as DOMRect);
  return screen.getByRole("tabpanel");
}

it("keeps the scroll position when clicking empty space first focuses the settings panel", () => {
  const panel = settings();
  vi.spyOn(panel, "getBoundingClientRect").mockReturnValue({ top: -400 } as DOMRect);
  fireEvent.focus(panel);
  expect(scrollBy).not.toHaveBeenCalled();
});

it("still brings a focused control out from behind the sticky settings tabs", () => {
  settings();
  const control = screen.getByRole("button", { name: "Change preference" });
  vi.spyOn(control, "getBoundingClientRect").mockReturnValue({ top: 45 } as DOMRect);
  fireEvent.focus(control);
  expect(scrollBy).toHaveBeenCalledExactlyOnceWith({ top: -27, behavior: "auto" });
});

it("leaves a visible control in place", () => {
  settings();
  const control = screen.getByRole("button", { name: "Change preference" });
  vi.spyOn(control, "getBoundingClientRect").mockReturnValue({ top: 200 } as DOMRect);
  fireEvent.focus(control);
  expect(scrollBy).not.toHaveBeenCalled();
});
