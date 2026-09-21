import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { WifiSettings } from "./WifiSettings";
import type { WifiPolicySnapshot } from "../../types";
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
  const toggle = await screen.findByRole("switch", { name: "Connect on Wi-Fi not marked trusted" });
  await waitFor(() => expect((toggle as HTMLInputElement).disabled).toBe(false));
  expect(screen.queryByRole("alert")).toBeNull();
  expect(mocks.setWifiPolicy).not.toHaveBeenCalled();
  fireEvent.click(toggle);
  await waitFor(() => expect(mocks.setWifiPolicy).toHaveBeenCalledWith({ enabled: true, server_id: "server-one" }));
  const input = screen.getByLabelText("Network name (optional)");
  await waitFor(() => expect((input as HTMLInputElement).disabled).toBe(false));
  fireEvent.change(input, { target: { value: "Home" } });
  fireEvent.click(screen.getByRole("button", { name: "Trust current Wi-Fi" }));
  await waitFor(() => expect(mocks.trustCurrentWifi).toHaveBeenCalledWith("network-one", "Home"));
});
it("keeps the saved opt-in visible when a native write fails", async () => {
  mocks.setWifiPolicy.mockRejectedValue(new Error("Could not save network policy"));
  render(<WifiSettings />);
  const toggle = await screen.findByRole("switch", { name: "Connect on Wi-Fi not marked trusted" });
  await waitFor(() => expect((toggle as HTMLInputElement).disabled).toBe(false));
  fireEvent.click(toggle);
  expect(await screen.findByText("Error: Could not save network policy")).toBeTruthy();
  expect((toggle as HTMLInputElement).checked).toBe(false);
});

it("does not send the OS display name when trusting a network without a friendly label", async () => {
  mocks.getWifiPolicy.mockResolvedValue({ ...initial, network_names: { "network-one": "Home hotspot" } });
  render(<WifiSettings />);
  const trust = await screen.findByRole("button", { name: "Trust current Wi-Fi" });
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
  const remove = await screen.findByRole("button", { name: "Remove trust for Home hotspot" });
  expect(within(remove.closest("li")!).getByText("Current network")).toBeTruthy();
  expect(screen.getByRole("button", { name: "Remove trust for Office hotspot" })).toBeTruthy();
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
  expect(await screen.findByText("Saved Wi-Fi (11111111)")).toBeTruthy();
  expect(screen.getByText("Saved Wi-Fi (22222222)")).toBeTruthy();
  expect(screen.getByText("Work")).toBeTruthy();
  expect(screen.getByText("Label: Family")).toBeTruthy();
  expect(screen.getAllByText(/OS name unavailable/)).toHaveLength(3);
});

it("shows why an unidentified Wi-Fi connection cannot be marked trusted", async () => {
  mocks.getWifiPolicy.mockResolvedValue({ ...initial, can_trust_current: false, current_network_token: null });
  render(<WifiSettings />);
  const trust = await screen.findByRole("button", { name: "Trust current Wi-Fi" });
  expect(trust.matches(":disabled")).toBe(true);
  expect(screen.getByText("The operating system cannot reliably identify this saved Wi-Fi connection. It cannot be marked trusted.")).toBeTruthy();
});

it("guides Android permission denial and requires an explicit trust action after granting access", async () => {
  mocks.android = true;
  mocks.getWifiPolicy.mockResolvedValue({ ...initial, can_trust_current: false, permission_required: true, location_enabled: true });
  mocks.invoke.mockResolvedValue(false);
  render(<WifiSettings />);
  fireEvent.click(await screen.findByRole("button", { name: "Allow Wi-Fi access" }));
  expect(await screen.findByText(/Wi-Fi access was not granted/)).toBeTruthy();
  expect(mocks.invoke).toHaveBeenCalledWith("android_wifi_permission");
  expect(screen.queryByRole("button", { name: "Trust current Wi-Fi" })).toBeNull();
  fireEvent.click(screen.getByRole("button", { name: "App permissions" }));
  expect(mocks.invoke).toHaveBeenCalledWith("android_background_wifi_settings");
  mocks.invoke.mockResolvedValue(true);
  mocks.getWifiPolicy.mockResolvedValue({ ...initial, current_network_token: "identified-network", permission_required: false, location_enabled: true });
  fireEvent.click(screen.getByRole("button", { name: "Allow Wi-Fi access" }));
  const trust = await screen.findByRole("button", { name: "Trust current Wi-Fi" });
  expect(trust.matches(":disabled")).toBe(false);
  expect(mocks.trustCurrentWifi).not.toHaveBeenCalled();
  fireEvent.click(trust);
  await waitFor(() => expect(mocks.trustCurrentWifi).toHaveBeenCalledWith("identified-network", "Wi-Fi exception"));
});

it("offers Android Location settings when permission is granted but Location is off", async () => {
  mocks.android = true;
  mocks.getWifiPolicy.mockResolvedValue({ ...initial, can_trust_current: false, permission_required: false, location_enabled: false });
  render(<WifiSettings />);
  fireEvent.click(await screen.findByRole("button", { name: "Open Location settings" }));
  expect(mocks.invoke).toHaveBeenCalledWith("android_location_settings");
  expect(screen.queryByRole("button", { name: "Allow Wi-Fi access" })).toBeNull();
  expect(mocks.trustCurrentWifi).not.toHaveBeenCalled();
});

it("refreshes a manual-disconnect pause but requires review when the network token changes", async () => {
  vi.useFakeTimers();
  mocks.getWifiPolicy.mockResolvedValue({ ...initial, policy: { enabled: true, server_id: "server-one" }, automation_status: "session_active" });
  await act(async () => { render(<WifiSettings />); });
  fireEvent.change(screen.getByLabelText("Network name (optional)"), { target: { value: "Home" } });
  mocks.getWifiPolicy.mockResolvedValue({ ...initial, policy: { enabled: true, server_id: "server-one" }, current_network_token: "network-two", automation_status: "waiting_for_network_change" });
  await act(async () => { await vi.advanceTimersByTimeAsync(5000); });
  expect(screen.getByText(/Automation paused on this network/)).toBeTruthy();
  expect(screen.getByRole("button", { name: "Trust current Wi-Fi" }).matches(":disabled")).toBe(true);
  expect(mocks.trustCurrentWifi).not.toHaveBeenCalled();
  await act(async () => { fireEvent.click(screen.getByRole("button", { name: "Refresh network" })); });
  expect((screen.getByLabelText("Network name (optional)") as HTMLInputElement).value).toBe("");
  await act(async () => { fireEvent.click(screen.getByRole("button", { name: "Trust current Wi-Fi" })); });
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
  expect(screen.getByRole("button", { name: "Trust current Wi-Fi" }).matches(":disabled")).toBe(true);
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
  expect(screen.getByText("The active connection is not Wi-Fi")).toBeTruthy();
  expect(screen.queryByText("Current network: marked trusted")).toBeNull();
});

it("lets a pending policy save finish across a hide and show without duplicate writes", async () => {
  let hidden = false;
  vi.spyOn(document, "hidden", "get").mockImplementation(() => hidden);
  let finish!: () => void;
  mocks.setWifiPolicy.mockReturnValue(new Promise<void>((resolve) => { finish = resolve; }));
  render(<WifiSettings />);
  const toggle = await screen.findByRole("switch", { name: "Connect on Wi-Fi not marked trusted" });
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
