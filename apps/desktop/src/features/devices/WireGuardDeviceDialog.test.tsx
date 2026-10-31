import { invoke } from "@tauri-apps/api/core";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { WireGuardDeviceDialog, wireguardFileName } from "./WireGuardDeviceDialog";
import { t } from "../../i18n";
import type { MemberPolicy } from "../../types";

vi.mock("@tauri-apps/api/core", () => ({ invoke: vi.fn(), Channel: vi.fn() }));

beforeEach(() => {
  vi.resetAllMocks();
  vi.mocked(invoke).mockResolvedValue({ device_id: "device", qr_svg: "<svg viewBox=\"0 0 29 29\"></svg>" });
});
afterEach(cleanup);

const props = { serverId: "server", target: null, onClose: vi.fn(), onCreated: vi.fn().mockResolvedValue(undefined) };
const policy: MemberPolicy = {
  device_limit: 3, expires_at_unix: null, weekly_access: [], invite_members: true,
  add_own_devices: true, manage_own_peer_communication: false, manage_own_port_forwards: false,
};

it("adds a new member's device and shows only the QR image, once", async () => {
  render(<WireGuardDeviceDialog {...props} />);
  const create = screen.getByRole("button", { name: t("devices.wireguard.create") }) as HTMLButtonElement;
  expect(create.disabled).toBe(true);
  fireEvent.change(screen.getByLabelText(t("devices.wireguard.memberName")), { target: { value: " Ayşe " } });
  fireEvent.change(screen.getByLabelText(t("devices.wireguard.deviceName")), { target: { value: "iPhone" } });
  fireEvent.click(create);
  await screen.findByAltText(t("devices.share.altWireguard"));
  expect(screen.getByText(t("devices.wireguard.secretWarning"))).toBeTruthy();
  expect(invoke).toHaveBeenCalledWith("create_wireguard_device", { input: {
    server_id: "server", member_name: "Ayşe", device_name: "iPhone",
    target_member_id: null, member_policy: undefined, path: null,
  } });
  expect(props.onCreated).toHaveBeenCalled();
});

it("adds to an existing member without a policy and limits a delegated member's grant", async () => {
  const target = { id: "family", name: "Family", role: "member" as const, devices: [] };
  render(<WireGuardDeviceDialog {...props} target={target} delegatedPolicy={policy} />);
  expect(screen.queryByLabelText(t("devices.wireguard.memberName"))).toBeNull();
  fireEvent.change(screen.getByLabelText(t("devices.wireguard.deviceName")), { target: { value: "Router" } });
  fireEvent.click(screen.getByRole("button", { name: t("devices.wireguard.create") }));
  await screen.findByAltText(t("devices.share.altWireguard"));
  expect(invoke).toHaveBeenLastCalledWith("create_wireguard_device", { input: expect.objectContaining({
    member_name: "Family", target_member_id: "family", member_policy: undefined,
  }) });
  cleanup();
  render(<WireGuardDeviceDialog {...props} delegatedPolicy={policy} />);
  fireEvent.change(screen.getByLabelText(t("devices.wireguard.memberName")), { target: { value: "Guest" } });
  fireEvent.change(screen.getByLabelText(t("devices.wireguard.deviceName")), { target: { value: "Tablet" } });
  fireEvent.click(screen.getByRole("button", { name: t("devices.wireguard.create") }));
  await screen.findByAltText(t("devices.share.altWireguard"));
  expect(invoke).toHaveBeenLastCalledWith("create_wireguard_device", { input: expect.objectContaining({
    member_policy: { ...policy, invite_members: false },
  }) });
});

it("suggests file names that wg-quick accepts as interface names", () => {
  expect(wireguardFileName("Ayşe's iPhone 15")).toBe("Ay-e-s-iPhone-1.conf");
  expect(wireguardFileName("GL.iNet router")).toBe("GL.iNet-router.conf");
  expect(wireguardFileName("...")).toBe("sirinvpn.conf");
});
