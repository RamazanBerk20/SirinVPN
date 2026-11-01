import { invoke } from "@tauri-apps/api/core";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { SubnetRoutesDialog, parseRoutes } from "./SubnetRoutesDialog";
import { DeviceList } from "./DeviceList";
import { t } from "../../i18n";
import type { MembershipSnapshot } from "../../types";

vi.mock("@tauri-apps/api/core", () => ({ invoke: vi.fn(), Channel: vi.fn() }));

beforeEach(() => {
  vi.resetAllMocks();
  vi.mocked(invoke).mockResolvedValue({ members: [], active_invitations: [] });
});
afterEach(cleanup);

const router = { id: "router", member_id: "owner", name: "Home server", client_tunnel_address: "10.77.0.5", subnet_routes: ["192.168.1.0/24"] };

it("replaces the whole list and an empty list stops sharing", async () => {
  const onSaved = vi.fn().mockResolvedValue(undefined), onClose = vi.fn();
  render(<SubnetRoutesDialog serverId="server" device={router} onClose={onClose} onSaved={onSaved} />);
  const field = screen.getByRole("textbox") as HTMLTextAreaElement;
  expect(field.value).toBe("192.168.1.0/24");
  fireEvent.change(field, { target: { value: " 192.168.1.0/24\n10.20.0.0/20, " } });
  fireEvent.click(screen.getByRole("button", { name: t("devices.localNetworks.save") }));
  await waitFor(() => expect(onClose).toHaveBeenCalled());
  expect(invoke).toHaveBeenCalledWith("update_device_subnet_routes", { input: {
    server_id: "server", device_id: "router", routes: ["192.168.1.0/24", "10.20.0.0/20"],
  } });
  expect(onSaved).toHaveBeenCalled();
  expect(parseRoutes("  \n ")).toEqual([]);
});

it("keeps the dialog open with the VPS's reason when it refuses a range", async () => {
  vi.mocked(invoke).mockRejectedValue("192.168.1.0/25 overlaps another subnet route");
  const onClose = vi.fn();
  render(<SubnetRoutesDialog serverId="server" device={router} onClose={onClose} onSaved={vi.fn()} />);
  fireEvent.click(screen.getByRole("button", { name: t("devices.localNetworks.save") }));
  expect((await screen.findByRole("alert")).textContent).toContain("overlaps");
  expect(onClose).not.toHaveBeenCalled();
});

it("offers local networks only to the Owner, on the Owner's own devices", () => {
  const snapshot: MembershipSnapshot = { active_invitations: [], members: [
    { id: "owner", name: "Owner", role: "owner", devices: [router] },
    { id: "family", name: "Family", role: "member", devices: [{ id: "phone", member_id: "family", name: "Phone", client_tunnel_address: "10.77.0.6" }] },
  ] };
  const onSubnetRoutes = vi.fn();
  const base = { snapshot, query: "", accessBusy: null, peerBusy: null, onInvite: vi.fn(), onAccess: vi.fn(),
    onTransfer: vi.fn(), onRename: vi.fn(), onRevoke: vi.fn(), onPeer: vi.fn(), onSubnetRoutes };
  const open = (name: string) => fireEvent.click(screen.getByRole("button", { name: t("devices.menu.deviceActions", { name }) }));
  render(<DeviceList {...base} accessLevel="owner" />);
  open("Home server");
  fireEvent.click(screen.getByRole("menuitem", { name: t("devices.menu.localNetworks") }));
  expect(onSubnetRoutes).toHaveBeenCalledWith(router);
  open("Phone");
  expect(screen.queryByRole("menuitem", { name: t("devices.menu.localNetworks") })).toBeNull();
  cleanup();
  // An Admin cannot manage the Owner's devices at all, so the row has no actions.
  render(<DeviceList {...base} accessLevel="admin" />);
  expect(screen.queryByRole("button", { name: t("devices.menu.deviceActions", { name: "Home server" }) })).toBeNull();
});

it("shows the ranges the VPS cannot route right now", () => {
  const blocked = { ...router, inactive_subnet_routes: ["192.168.1.0/24"] };
  const snapshot: MembershipSnapshot = { active_invitations: [], members: [
    { id: "owner", name: "Owner", role: "owner", devices: [blocked] },
  ] };
  render(<DeviceList snapshot={snapshot} query="" accessBusy={null} peerBusy={null} onInvite={vi.fn()} onAccess={vi.fn()}
    onTransfer={vi.fn()} onRename={vi.fn()} onRevoke={vi.fn()} onPeer={vi.fn()} onSubnetRoutes={vi.fn()} accessLevel="owner" />);
  const label = screen.getByText(t("devices.row.facts.inactiveLocalNetworks"));
  expect(label.nextElementSibling?.textContent).toBe("192.168.1.0/24");
});
