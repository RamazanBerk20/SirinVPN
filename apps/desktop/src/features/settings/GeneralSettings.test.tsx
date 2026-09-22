import { afterEach, beforeEach, expect, it, vi } from "vitest";
import {
  cleanup,
  act,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import { GeneralSettings } from "./GeneralSettings";
import { PreferencesProvider } from "./PreferencesProvider";
import type { PreferencesSnapshot } from "./preferences";

const mocks = vi.hoisted(() => ({
  getAppPreferences: vi.fn(),
  getWifiPolicy: vi.fn(),
  listServers: vi.fn(),
  setAppPreferences: vi.fn(),
  requestNotificationPermission: vi.fn(),
  testNotification: vi.fn(),
  invoke: vi.fn(),
  android: false,
}));
vi.mock("../../api", () => ({ api: mocks }));
vi.mock("../../platform", () => ({ get isAndroid() { return mocks.android; }, invoke: mocks.invoke }));
const initial: PreferencesSnapshot = {
  preferences: {
    start_on_login: false,
    launch_minimized: false,
    close_to_tray: false,
    notifications: false,
    animations: true,
  },
  startup_available: true,
  tray_available: true,
  notification_permission: "granted",
};
beforeEach(() => {
  vi.resetAllMocks();
  mocks.android = false;
  mocks.listServers.mockResolvedValue([]);
  mocks.getWifiPolicy.mockResolvedValue({ policy: { enabled: false, server_id: null }, trusted_networks: [], current_network: "unavailable", can_trust_current: false, current_network_token: null, automation_status: "disabled" });
  mocks.getAppPreferences.mockResolvedValue(structuredClone(initial));
  mocks.setAppPreferences.mockImplementation(async (preferences) => ({
    ...initial,
    preferences,
  }));
  mocks.requestNotificationPermission.mockResolvedValue("granted");
  mocks.invoke.mockResolvedValue({ quick_profile: null });
});
afterEach(cleanup);
function setup(platform: "desktop" | "android" = "desktop") {
  return render(
    <PreferencesProvider>
      <GeneralSettings platform={platform} />
    </PreferencesProvider>,
  );
}

it("shows Android policy controls, denied-notification guidance and the older tile instructions", async () => {
  mocks.getAppPreferences.mockResolvedValue({ ...initial, notification_permission: "denied" });
  mocks.invoke.mockImplementation(async command => command === "android_add_tile" ? "Open Quick Settings, tap Edit and add SirinVPN." : { quick_profile: null });
  setup("android");
  expect(await screen.findByText(/Android is hiding SirinVPN notifications/)).toBeTruthy();
  expect(screen.queryByText("Startup & window")).toBeNull();
  expect(screen.queryByText("Local VPN component")).toBeNull();
  fireEvent.click(screen.getByRole("button", { name: "Add Quick Settings tile" }));
  expect(await screen.findByText("Open Quick Settings, tap Edit and add SirinVPN.")).toBeTruthy();
});
it("shows notifications off when Android permission is missing even if the saved preference is on", async () => {
  mocks.getAppPreferences.mockResolvedValue({ ...initial, preferences: { ...initial.preferences, notifications: true }, notification_permission: "denied" });
  setup("android");
  const input = await screen.findByRole("switch", { name: "Connection notifications" });
  expect((input as HTMLInputElement).checked).toBe(false);
  await waitFor(() => expect(input.matches(":disabled")).toBe(false));
  fireEvent.click(input);
  await waitFor(() => expect(mocks.requestNotificationPermission).toHaveBeenCalledOnce());
});
it("refreshes Android notification access after the test action grants permission", async () => {
  mocks.android = true;
  const preferences = { ...initial.preferences, notifications: true };
  mocks.getAppPreferences.mockResolvedValue({ ...initial, preferences, notification_permission: "denied" });
  mocks.testNotification.mockImplementation(async () => {
    mocks.getAppPreferences.mockResolvedValue({ ...initial, preferences, notification_permission: "granted" });
  });
  setup("android");
  const button = await screen.findByRole("button", { name: "Test notification" });
  await waitFor(() => expect(button.matches(":disabled")).toBe(false));
  fireEvent.click(button);
  await waitFor(() => expect((screen.getByRole("switch", { name: "Connection notifications" }) as HTMLInputElement).checked).toBe(true));
});
async function toggle(name: string) {
  const input = (await screen.findByRole("switch", {
    name,
  })) as HTMLInputElement;
  await waitFor(() => expect(input.disabled).toBe(false));
  fireEvent.click(input);
  return input;
}

it("retains the previous preference when a native save fails", async () => {
  mocks.setAppPreferences.mockRejectedValue(
    new Error("Startup registration failed"),
  );
  setup();
  const input = await toggle("Start on system startup");
  expect(await screen.findByText("Startup registration failed")).toBeTruthy();
  expect(input.checked).toBe(false);
});

it("ignores an older Android refresh after a newer refresh and switch save", async () => {
  mocks.android = true;
  setup("android");
  const input = await screen.findByRole("switch", { name: "Interface animations" }) as HTMLInputElement;
  await waitFor(() => expect(input.disabled).toBe(false));
  let resolveOld!: (value: PreferencesSnapshot) => void;
  mocks.getAppPreferences.mockImplementationOnce(() => new Promise(resolve => { resolveOld = resolve; }));
  fireEvent(document, new Event("visibilitychange"));
  fireEvent(document, new Event("visibilitychange"));
  await waitFor(() => expect(input.disabled).toBe(false));
  fireEvent.click(input);
  await waitFor(() => expect(input.checked).toBe(false));
  await act(async () => { resolveOld(structuredClone(initial)); });
  expect(input.checked).toBe(false);
  expect(document.documentElement.dataset.motion).toBe("reduced");
});

it("requests permission before enabling notifications and never saves a denial", async () => {
  mocks.requestNotificationPermission.mockResolvedValue("denied");
  setup();
  const input = await toggle("Connection notifications");
  expect(await screen.findByText(/Notifications are blocked/)).toBeTruthy();
  expect(mocks.setAppPreferences).not.toHaveBeenCalled();
  expect(input.checked).toBe(false);
});

it("saves allowed notifications and sends a native test only on request", async () => {
  setup();
  const input = await toggle("Connection notifications");
  await waitFor(() => expect(input.checked).toBe(true));
  expect(mocks.requestNotificationPermission).toHaveBeenCalledTimes(1);
  expect(mocks.testNotification).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole("button", { name: "Test notification" }));
  await waitFor(() => expect(mocks.testNotification).toHaveBeenCalledTimes(1));
});

it("restores reduced motion after the app reloads", async () => {
  mocks.getAppPreferences.mockResolvedValue({
    ...initial,
    preferences: { ...initial.preferences, animations: false },
  });
  setup();
  await waitFor(() =>
    expect(document.documentElement.dataset.motion).toBe("reduced"),
  );
  expect(
    (
      screen.getByRole("switch", {
        name: "Interface animations",
      }) as HTMLInputElement
    ).checked,
  ).toBe(false);
});

it("locks unavailable tray and startup controls while other preferences remain usable", async () => {
  mocks.getAppPreferences.mockResolvedValue({
    ...initial,
    startup_available: false,
    tray_available: false,
  });
  mocks.setAppPreferences.mockImplementation(async (preferences) => ({
    ...initial,
    startup_available: false,
    tray_available: false,
    preferences,
  }));
  setup();
  const animation = await toggle("Interface animations");
  await waitFor(() => expect(animation.checked).toBe(false));
  expect(
    (screen.getByRole("switch", { name: "Close to tray" }) as HTMLInputElement)
      .disabled,
  ).toBe(true);
  expect(
    (
      screen.getByRole("switch", {
        name: "Start on system startup",
      }) as HTMLInputElement
    ).disabled,
  ).toBe(true);
});

it("keeps settings disabled when the native store cannot be read", async () => {
  mocks.getAppPreferences.mockRejectedValue(
    new Error("Settings could not be read"),
  );
  setup();
  expect(await screen.findByText("Settings could not be read")).toBeTruthy();
  expect(
    (
      screen.getByRole("switch", {
        name: "Connection notifications",
      }) as HTMLInputElement
    ).disabled,
  ).toBe(true);
  expect(mocks.setAppPreferences).not.toHaveBeenCalled();
});
