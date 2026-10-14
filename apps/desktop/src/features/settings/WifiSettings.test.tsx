import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { WifiSettings } from "./WifiSettings";
import type { WifiPolicySnapshot } from "../../types";
import { t } from "../../i18n";
const mocks = vi.hoisted(() => ({ getWifiPolicy: vi.fn(), listServers: vi.fn(), setWifiPolicy: vi.fn(), trustCurrentWifi: vi.fn(), forgetTrustedWifi: vi.fn(), invoke: vi.fn(), android: false }));
vi.mock("../../api", () => ({ api: mocks }));
vi.mock("../../platform", () => ({ get isAndroid() { return mocks.android; }, invoke: mocks.invoke }));
const initial: WifiPolicySnapshot = { policy: { enabled: false, server_id: null }, trusted_networks: [], current_network: "untrusted_wifi", current_network_token: "network-one", can_trust_current: true, automation_status: "disabled" };
beforeEach(() => {
  vi.resetAllMocks();
  mocks.android = false;
  mocks.getWifiPolicy.mockResolvedValue(structuredClone(initial));
  mocks.listServers.mockResolvedValue([{ id: "server-one", name: "Personal VPS" }]);
});
afterEach(() => { cleanup(); vi.useRealTimers(); vi.restoreAllMocks(); });
it("requires an explicit opt-in and binds trust to the reviewed network", async () => {
  render(<WifiSettings />);
  const toggle = await screen.findByRole("switch", { name: t("settings.wifi.toggle.label") });
  await waitFor(() => expect((toggle as HTMLInputElement).disabled).toBe(false));
  expect(screen.queryByRole("alert")).toBeNull();
  expect(mocks.setWifiPolicy).not.toHaveBeenCalled();
  fireEvent.click(toggle);
  await waitFor(() => expect(mocks.setWifiPolicy).toHaveBeenCalledWith({ enabled: true, server_id: "server-one" }));
  const input = screen.getByLabelText(t("settings.wifi.trust.label"));
  await waitFor(() => expect((input as HTMLInputElement).disabled).toBe(false));
  fireEvent.change(input, { target: { value: "Home" } });
  fireEvent.click(screen.getByRole("button", { name: t("settings.wifi.trust.action") }));
  await waitFor(() => expect(mocks.trustCurrentWifi).toHaveBeenCalledWith("network-one", "Home"));
});
it("keeps the saved opt-in visible when a native write fails", async () => {
  mocks.setWifiPolicy.mockRejectedValue(new Error("Could not save network policy"));
  render(<WifiSettings />);
  const toggle = await screen.findByRole("switch", { name: t("settings.wifi.toggle.label") });
  await waitFor(() => expect((toggle as HTMLInputElement).disabled).toBe(false));
  fireEvent.click(toggle);
  expect(await screen.findByText("Could not save network policy")).toBeTruthy();
  expect((toggle as HTMLInputElement).checked).toBe(false);
});

it("does not send the OS display name when trusting a network without a friendly label", async () => {
  mocks.getWifiPolicy.mockResolvedValue({ ...initial, network_names: { "network-one": "Home hotspot" } });
  render(<WifiSettings />);
  const trust = await screen.findByRole("button", { name: t("settings.wifi.trust.action") });
  expect(trust.matches(":disabled")).toBe(false);
  fireEvent.click(trust);
  await waitFor(() => expect(mocks.trustCurrentWifi).toHaveBeenCalledWith("network-one", "Wi-Fi exception"));
});

it("resolves existing generic entries, marks the current hotspot, and removes the selected ID", async () => {
  mocks.getWifiPolicy.mockResolvedValue({ ...initial, current_network: "trusted_wifi",
    trusted_networks: [{ id: "network-one", label: "Wi-Fi exception" }, { id: "network-two", label: "Wi-Fi exception" }],
    network_names: { "network-one": "Home hotspot", "network-two": "Office hotspot" },
  });
  render(<WifiSettings />);
  const remove = await screen.findByRole("button", { name: t("settings.wifi.trusted.removeLabel", { name: "Home hotspot" }) });
  expect(within(remove.closest("li")!).getByText(t("settings.wifi.trusted.current"))).toBeTruthy();
  expect(screen.getByRole("button", { name: t("settings.wifi.trusted.removeLabel", { name: "Office hotspot" }) })).toBeTruthy();
  expect(screen.queryByText("Wi-Fi exception")).toBeNull();
  fireEvent.click(remove);
  await waitFor(() => expect(mocks.forgetTrustedWifi).toHaveBeenCalledWith("network-one"));
});

it("preserves friendly labels and distinguishes unnamed profiles when OS names are unavailable", async () => {
  mocks.getWifiPolicy.mockResolvedValue({ ...initial, trusted_networks: [
    { id: "11111111aaaa", label: "Wi-Fi exception" }, { id: "22222222bbbb", label: "Wi-Fi exception" },
    { id: "office", label: "Work" }, { id: "home", label: "Family" },
  ], network_names: { home: "Home hotspot" } });
  render(<WifiSettings />);
  expect(await screen.findByText(t("settings.wifi.trusted.savedName", { id: "11111111" }))).toBeTruthy();
  expect(screen.getByText(t("settings.wifi.trusted.savedName", { id: "22222222" }))).toBeTruthy();
  expect(screen.getByText("Work")).toBeTruthy();
  expect(screen.getByText(t("settings.wifi.trusted.label", { label: "Family" }))).toBeTruthy();
  expect(screen.getAllByText(t("settings.wifi.trusted.nameUnavailable"), { exact: false })).toHaveLength(3);
});

it("shows why an unidentified Wi-Fi connection cannot be marked trusted", async () => {
  mocks.getWifiPolicy.mockResolvedValue({ ...initial, can_trust_current: false, current_network_token: null });
  render(<WifiSettings />);
  const trust = await screen.findByRole("button", { name: t("settings.wifi.trust.action") });
  expect(trust.matches(":disabled")).toBe(true);
  expect(screen.getByText(t("settings.wifi.access.unidentified"))).toBeTruthy();
});

it("guides Android permission denial and requires an explicit trust action after granting access", async () => {
  mocks.android = true;
  mocks.getWifiPolicy.mockResolvedValue({ ...initial, can_trust_current: false, permission_required: true, location_enabled: true });
  mocks.invoke.mockResolvedValue(false);
  render(<WifiSettings />);
  fireEvent.click(await screen.findByRole("button", { name: t("settings.wifi.access.allow") }));
  expect(await screen.findByText(t("settings.wifi.access.denied"))).toBeTruthy();
  expect(mocks.invoke).toHaveBeenCalledWith("android_wifi_permission");
  expect(screen.queryByRole("button", { name: t("settings.wifi.trust.action") })).toBeNull();
  fireEvent.click(screen.getByRole("button", { name: t("settings.wifi.access.appPermissions") }));
  expect(mocks.invoke).toHaveBeenCalledWith("android_background_wifi_settings");
  mocks.invoke.mockResolvedValue(true);
  mocks.getWifiPolicy.mockResolvedValue({ ...initial, current_network_token: "identified-network", permission_required: false, location_enabled: true });
  fireEvent.click(screen.getByRole("button", { name: t("settings.wifi.access.allow") }));
  const trust = await screen.findByRole("button", { name: t("settings.wifi.trust.action") });
  expect(trust.matches(":disabled")).toBe(false);
  expect(mocks.trustCurrentWifi).not.toHaveBeenCalled();
  fireEvent.click(trust);
  await waitFor(() => expect(mocks.trustCurrentWifi).toHaveBeenCalledWith("identified-network", "Wi-Fi exception"));
});

it("offers Android Location settings when permission is granted but Location is off", async () => {
  mocks.android = true;
  mocks.getWifiPolicy.mockResolvedValue({ ...initial, can_trust_current: false, permission_required: false, location_enabled: false });
  render(<WifiSettings />);
  fireEvent.click(await screen.findByRole("button", { name: t("settings.wifi.access.locationSettings") }));
  expect(mocks.invoke).toHaveBeenCalledWith("android_location_settings");
  expect(screen.queryByRole("button", { name: t("settings.wifi.access.allow") })).toBeNull();
  expect(mocks.trustCurrentWifi).not.toHaveBeenCalled();
});

it("refreshes a manual-disconnect pause but requires review when the network token changes", async () => {
  vi.useFakeTimers();
  mocks.getWifiPolicy.mockResolvedValue({ ...initial, policy: { enabled: true, server_id: "server-one" }, automation_status: "session_active" });
  await act(async () => { render(<WifiSettings />); });
  fireEvent.change(screen.getByLabelText(t("settings.wifi.trust.label")), { target: { value: "Home" } });
  mocks.getWifiPolicy.mockResolvedValue({ ...initial, policy: { enabled: true, server_id: "server-one" }, current_network_token: "network-two", automation_status: "waiting_for_network_change" });
  await act(async () => { await vi.advanceTimersByTimeAsync(5000); });
  expect(screen.getByText(t("settings.wifi.status.paused"))).toBeTruthy();
  expect(screen.getByRole("button", { name: t("settings.wifi.trust.action") }).matches(":disabled")).toBe(true);
  expect(mocks.trustCurrentWifi).not.toHaveBeenCalled();
  await act(async () => { fireEvent.click(screen.getByRole("button", { name: t("settings.wifi.refresh") })); });
  expect((screen.getByLabelText(t("settings.wifi.trust.label")) as HTMLInputElement).value).toBe("");
  await act(async () => { fireEvent.click(screen.getByRole("button", { name: t("settings.wifi.trust.action") })); });
  expect(mocks.trustCurrentWifi).toHaveBeenCalledWith("network-two", "Wi-Fi exception");
});

it("pauses hidden network reads and refreshes on return without trusting a changed network", async () => {
  vi.useFakeTimers();
  let hidden = false;
  vi.spyOn(document, "hidden", "get").mockImplementation(() => hidden);
  await act(async () => { render(<WifiSettings />); });
  const initialReads = mocks.getWifiPolicy.mock.calls.length;
  await act(async () => {
    hidden = true; document.dispatchEvent(new Event("visibilitychange"));
    await vi.advanceTimersByTimeAsync(60_000);
  });
  expect(mocks.getWifiPolicy).toHaveBeenCalledTimes(initialReads);
  mocks.getWifiPolicy.mockResolvedValue({ ...initial, current_network_token: "network-two" });
  await act(async () => { hidden = false; document.dispatchEvent(new Event("visibilitychange")); });
  expect(mocks.getWifiPolicy).toHaveBeenCalledTimes(initialReads + 1);
  expect(mocks.listServers).toHaveBeenCalledOnce();
  expect(screen.getByRole("button", { name: t("settings.wifi.trust.action") }).matches(":disabled")).toBe(true);
  expect(mocks.trustCurrentWifi).not.toHaveBeenCalled();
});

it("discards a read started before hiding and refreshes once it settles", async () => {
  vi.useFakeTimers();
  let hidden = false;
  vi.spyOn(document, "hidden", "get").mockImplementation(() => hidden);
  await act(async () => { render(<WifiSettings />); });
  let finish!: (snapshot: WifiPolicySnapshot) => void;
  mocks.getWifiPolicy.mockReturnValueOnce(new Promise<WifiPolicySnapshot>((resolve) => { finish = resolve; }));
  await act(async () => { await vi.advanceTimersByTimeAsync(5000); });
  await act(async () => { hidden = true; document.dispatchEvent(new Event("visibilitychange")); });
  await act(async () => { hidden = false; document.dispatchEvent(new Event("visibilitychange")); });
  expect(mocks.getWifiPolicy).toHaveBeenCalledTimes(2);
  mocks.getWifiPolicy.mockResolvedValue({ ...initial, current_network: "other_network", current_network_token: "network-new" });
  await act(async () => { finish({ ...initial, current_network: "trusted_wifi", current_network_token: "network-old" }); });
  expect(mocks.getWifiPolicy).toHaveBeenCalledTimes(3);
  expect(screen.getByText(t("settings.wifi.network.otherNetwork"))).toBeTruthy();
  expect(screen.queryByText(t("settings.wifi.network.trusted"))).toBeNull();
});

it("lets a pending policy save finish across a hide and show without duplicate writes", async () => {
  let hidden = false;
  vi.spyOn(document, "hidden", "get").mockImplementation(() => hidden);
  let finish!: () => void;
  mocks.setWifiPolicy.mockReturnValue(new Promise<void>((resolve) => { finish = resolve; }));
  render(<WifiSettings />);
  const toggle = await screen.findByRole("switch", { name: t("settings.wifi.toggle.label") });
  await waitFor(() => expect(toggle.matches(":disabled")).toBe(false));
  fireEvent.click(toggle);
  act(() => { hidden = true; document.dispatchEvent(new Event("visibilitychange")); });
  act(() => { hidden = false; document.dispatchEvent(new Event("visibilitychange")); });
  mocks.getWifiPolicy.mockResolvedValue({ ...initial, policy: { enabled: true, server_id: "server-one" } });
  await act(async () => finish());
  expect(mocks.setWifiPolicy).toHaveBeenCalledOnce();
  expect((toggle as HTMLInputElement).checked).toBe(true);
  expect(toggle.matches(":disabled")).toBe(false);
});

it("clears a failed first read once a later poll succeeds", async () => {
  vi.useFakeTimers();
  mocks.getWifiPolicy.mockRejectedValueOnce(new Error("Wi-Fi state is temporarily unavailable"));
  await act(async () => { render(<WifiSettings />); });
  expect(screen.getByText("Wi-Fi state is temporarily unavailable")).toBeTruthy();
  await act(async () => { await vi.advanceTimersByTimeAsync(5000); });
  expect(screen.queryByText("Wi-Fi state is temporarily unavailable")).toBeNull();
  expect(screen.getByRole("switch", { name: t("settings.wifi.toggle.label") })).toBeTruthy();
});
