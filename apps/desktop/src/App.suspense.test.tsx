import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { act, cleanup, fireEvent, render, screen } from "@testing-library/react";
import App from "./App";
import { t } from "./i18n";

const apiMocks = vi.hoisted(() => ({
  getAppPreferences: vi.fn(), clientPlatform: vi.fn(), listServers: vi.fn(), localStatus: vi.fn(),
  releaseUpdateStatus: vi.fn(),
}));
vi.mock("./api", () => ({ api: apiMocks }));
// A slow chunk: the settings module resolves only when the test says so.
const gate = vi.hoisted(() => { let open!: () => void; const ready = new Promise<void>(resolve => { open = resolve; }); return { ready, open }; });
vi.mock("./features/settings/GeneralSettings", async (original) => { await gate.ready; return original(); });

beforeEach(() => {
  apiMocks.getAppPreferences.mockResolvedValue({ preferences: { start_on_login: false, launch_minimized: false, close_to_tray: false, notifications: false, animations: true },
    startup_available: true, tray_available: true, notification_permission: "granted" });
  apiMocks.clientPlatform.mockResolvedValue("desktop");
  apiMocks.listServers.mockResolvedValue([]);
  apiMocks.localStatus.mockResolvedValue({ state: "disconnected", rx_bytes: 0, tx_bytes: 0, kill_switch_enabled: false, auto_reconnect_enabled: false, routing_mode: "full_tunnel" });
  apiMocks.releaseUpdateStatus.mockResolvedValue({ installer_kind: "debian", rollback_version: null, baseline_required: false });
});
afterEach(cleanup);

it("keeps the visible screen while a lazily loaded dialog is still loading", async () => {
  render(<App />);
  const settings = await screen.findByRole("button", { name: t("app.onboarding.settings") }, { timeout: 5_000 });
  fireEvent.click(settings);
  // The full-screen loader is for boot only; the onboarding screen stays on screen (the modal hides it from the accessibility tree, not from view).
  const shown = () => (document.querySelector(".onboarding-shell") as HTMLElement | null)?.style.display !== "none" && !document.querySelector(".loading-screen");
  expect(shown()).toBe(true);
  await act(async () => { gate.open(); await gate.ready; });
  expect(await screen.findByRole("dialog", { name: t("app.onboarding.settings") })).toBeTruthy();
  expect(shown()).toBe(true);
});
