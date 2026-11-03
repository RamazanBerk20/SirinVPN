import { afterEach, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { DeviceList } from "./DeviceList";
import { t } from "../../i18n";
import type { MembershipSnapshot } from "../../types";

afterEach(cleanup);
const snapshot: MembershipSnapshot = {
  members: [
    {
      id: "owner",
      name: "Owner",
      role: "owner",
      devices: [
        {
          id: "desktop",
          member_id: "owner",
          name: "My desktop",
          client_tunnel_address: "10.77.0.2",
        },
      ],
    },
    {
      id: "member",
      name: "Family",
      role: "member",
      devices: [
        {
          id: "phone",
          member_id: "member",
          name: "Android phone",
          client_tunnel_address: "10.77.0.3",
          recent_handshake: true,
        },
      ],
    },
    {
      id: "admin",
      name: "Administrator",
      role: "member",
      administrator: true,
      devices: [
        {
          id: "admin-device",
          member_id: "admin",
          name: "Admin laptop",
          client_tunnel_address: "10.77.0.4",
        },
      ],
    },
  ],
  active_invitations: [],
};
function setup(overrides: Partial<Parameters<typeof DeviceList>[0]> = {}) {
  const props = {
    snapshot,
    accessLevel: "owner" as const,
    currentDeviceId: "desktop",
    query: "",
    accessBusy: null,
    peerBusy: null,
    onInvite: vi.fn(),
    onAccess: vi.fn(),
    onTransfer: vi.fn(),
    onRename: vi.fn(),
    onRevoke: vi.fn(),
    onPeer: vi.fn(),
    ...overrides,
  };
  render(<DeviceList {...props} />);
  return props;
}
function menu(name: string) {
  fireEvent.click(screen.getByRole("button", { name: t("devices.menu.deviceActions", { name }) }));
}
function memberMenu(name: string) {
  fireEvent.click(screen.getByRole("button", { name: t("devices.menu.memberActions", { name }) }));
}
const item = (name: string) => screen.getByRole("menuitem", { name }) as HTMLButtonElement;
const items = () => screen.getAllByRole("menuitem").map((element) => element.textContent);
const closeMenu = () => fireEvent.keyDown(screen.getByRole("menu"), { key: "Escape" });

it.each([
  ["desktop", "desktop", "owner"],
  ["desktop", "phone", "member"],
  ["desktop", "admin-device", "admin"],
] as const)("shows one shared device name on %s when viewed by %s", (platform, currentDeviceId, accessLevel) => {
  setup({
    platform,
    currentDeviceId,
    accessLevel,
    query: "10.77.0.2",
    snapshot: {
      ...snapshot,
      members: snapshot.members.map(member => member.id === "owner" ? {
        ...member,
        devices: member.devices.map(device => ({ ...device, name: "Owner device" })),
      } : member),
    },
  });
  expect(screen.getAllByText("Owner device", { exact: true })).toHaveLength(1);
  expect(screen.queryByText("My computer")).toBeNull();
  expect(screen.queryByText("My Android device")).toBeNull();
  expect(screen.queryByText("Saved device name")).toBeNull();
  expect(screen.queryByText("Access group")).toBeNull();
  expect(Boolean(screen.queryByText(t("common.noun.thisDevice")))).toBe(currentDeviceId === "desktop");
});

it("groups devices under their member, with the role, limits and address", () => {
  const limited = { ...snapshot.members[1], policy: { device_limit: 2, expires_at_unix: null, weekly_access: [{ start_minute: 540, end_minute: 1020 }],
    invite_members: true, add_own_devices: false, manage_own_peer_communication: false, manage_own_port_forwards: false } };
  setup({ snapshot: { ...snapshot, members: [snapshot.members[0], limited] } });
  const family = screen.getByRole("region", { name: "Family" });
  expect(within(family).getByText(t("common.role.member"))).toBeTruthy();
  expect(within(family).getByText(t("devices.member.devicesOfLimit", { count: 1, limit: 2 }))).toBeTruthy();
  expect(within(family).getByText(t("devices.member.limitedHours"))).toBeTruthy();
  expect(within(family).getByText(t("devices.member.canInvite"))).toBeTruthy();
  const phone = within(family).getByText("Android phone").closest(".device-item")!.querySelector("small")!;
  expect(phone.textContent).toBe("10.77.0.3");
  expect(within(screen.getByRole("region", { name: "Owner" })).queryByText(t("devices.member.limitedHours"))).toBeNull();
});

it("keeps device actions on the device and member actions on the member", () => {
  const props = setup({ query: "10.77.0.3" });
  expect(screen.queryByText("My desktop")).toBeNull();
  menu("Android phone");
  expect(screen.queryByRole("menuitem", { name: t("devices.menu.addDeviceFor", { name: "Family" }) })).toBeNull();
  expect(screen.queryByRole("menuitem", { name: t("devices.menu.makeAdmin") })).toBeNull();
  fireEvent.click(item(t("devices.menu.rename")));
  menu("Android phone");
  fireEvent.click(item(t("devices.menu.allowMutual")));
  memberMenu("Family");
  fireEvent.click(item(t("devices.menu.addDeviceFor", { name: "Family" })));
  memberMenu("Family");
  fireEvent.click(item(t("devices.menu.makeAdmin")));
  expect(props.onRename).toHaveBeenCalledWith("phone", "Android phone");
  expect(props.onPeer).toHaveBeenCalledWith("phone", "Android phone", false);
  expect(props.onInvite).toHaveBeenCalledWith(snapshot.members[1]);
  expect(props.onAccess).toHaveBeenCalledWith(snapshot.members[1]);
});

it("finds a member by name with all their devices, and offers to clear a search with no result", () => {
  const onClearSearch = vi.fn();
  setup({ query: "family" });
  expect(screen.getByText("Android phone")).toBeTruthy();
  expect(screen.queryByText("My desktop")).toBeNull();
  cleanup();
  setup({ query: "nothing like this", onClearSearch });
  expect(screen.getByRole("status").textContent).toContain(t("devices.panel.noMatches", { query: "nothing like this" }));
  fireEvent.click(screen.getByRole("button", { name: t("devices.panel.clearSearch") }));
  expect(onClearSearch).toHaveBeenCalled();
});

it("preserves last-owner and pending invitation restrictions with visible reasons", () => {
  setup({
    snapshot: {
      ...snapshot,
      active_invitations: [
        {
          id: "invite",
          member_name: "Family",
          device_name: "Tablet",
          target_member_id: "member",
          expires_at_unix: 123456789,
        },
      ],
    },
  });
  menu("My desktop");
  expect(item(t("devices.menu.revoke", { name: "My desktop" })).disabled).toBe(true);
  expect(screen.getAllByText(t("devices.row.lastOwnerDevice"))[0]).toBeTruthy();
  closeMenu();
  expect(document.activeElement).toBe(
    screen.getByRole("button", { name: t("devices.menu.deviceActions", { name: "My desktop" }) }),
  );
  memberMenu("Family");
  expect(item(t("devices.menu.makeAdmin")).disabled).toBe(true);
  expect(item(t("devices.menu.transfer")).disabled).toBe(true);
  expect(screen.getAllByText(t("devices.menu.cancelInvitationFirst")).length).toBeGreaterThan(0);
});

it("limits Admin controls and states unknown activity directly in the row", () => {
  const props = setup({
    accessLevel: "admin",
    currentDeviceId: "admin-device",
  });
  // Rows the Admin can't manage still open their details, and nothing else.
  for (const name of ["My desktop", "Admin laptop"]) {
    menu(name);
    expect(items()).toEqual([t("devices.menu.details")]);
    closeMenu();
  }
  expect(screen.queryByRole("button", { name: t("devices.menu.memberActions", { name: "Owner" }) })).toBeNull();
  expect(screen.getByText(t("devices.row.activity.unknown"))).toBeTruthy();
  expect(screen.getByText(t("devices.row.activity.recent"))).toBeTruthy();
  menu("Android phone");
  fireEvent.click(item(t("devices.menu.revoke", { name: "Android phone" })));
  expect(props.onRevoke).toHaveBeenCalledWith("phone", "Android phone");
  // An Admin may add a Member's devices, and nothing more without lifecycle support.
  memberMenu("Family");
  expect(items()).toEqual([t("devices.menu.addDeviceFor", { name: "Family" })]);
});

it("offers member actions only with server support and never on the Owner", () => {
  const props = setup({
    memberLifecycleAvailable: true,
    onMemberSuspension: vi.fn(),
    onRevokeMemberDevices: vi.fn(),
  });
  // The Owner's own menu only adds devices: no suspension or revocation.
  memberMenu("Owner");
  expect(items()).toEqual([t("devices.menu.addDeviceFor", { name: "Owner" })]);
  closeMenu();
  memberMenu("Family");
  fireEvent.click(item(t("devices.menu.suspend")));
  expect(props.onMemberSuspension).toHaveBeenCalledWith(snapshot.members[1]);
  memberMenu("Family");
  fireEvent.click(item(t("devices.menu.revokeAll")));
  expect(props.onRevokeMemberDevices).toHaveBeenCalledWith(snapshot.members[1]);
  cleanup();
  setup();
  memberMenu("Family");
  expect(screen.queryByRole("menuitem", { name: t("devices.menu.suspend") })).toBeNull();
});

it("marks a suspended member and prevents enrollment and ownership transfer", () => {
  const suspended = { ...snapshot.members[1], suspended: true };
  const props = setup({
    memberLifecycleAvailable: true,
    onMemberSuspension: vi.fn(),
    snapshot: { ...snapshot, members: [snapshot.members[0], suspended] },
  });
  const family = screen.getByRole("region", { name: "Family" });
  expect(within(family).getAllByText(t("devices.member.suspended")).length).toBe(2);
  expect(screen.queryByText(t("devices.row.activity.recent"))).toBeNull();
  memberMenu("Family");
  expect(item(t("devices.menu.addDeviceFor", { name: "Family" })).disabled).toBe(true);
  expect(item(t("devices.menu.transfer")).disabled).toBe(true);
  fireEvent.click(item(t("devices.menu.reactivate")));
  expect(props.onMemberSuspension).toHaveBeenCalledWith(suspended);
});

it("explains a reached device limit on the card and on the disabled Add device", () => {
  const full = { ...snapshot.members[1], policy: { device_limit: 1, expires_at_unix: null, weekly_access: [], invite_members: false,
    add_own_devices: true, manage_own_peer_communication: false, manage_own_port_forwards: false } };
  setup({ snapshot: { ...snapshot, members: [snapshot.members[0], full] } });
  const reason = t("devices.menu.limitReached", { count: 1 });
  expect(within(screen.getByRole("region", { name: "Family" })).getByText(reason)).toBeTruthy();
  memberMenu("Family");
  const add = item(t("devices.menu.addDeviceFor", { name: "Family" }));
  expect(add.disabled).toBe(true);
  // Screen readers get the reason as the item's description.
  expect(document.getElementById(add.getAttribute("aria-describedby")!)?.textContent).toBe(reason);
});

it("ends a device's menu with Revoke, after its Advanced group", () => {
  setup();
  menu("Android phone");
  expect(items().at(-1)).toBe(t("devices.menu.revoke", { name: "Android phone" }));
  expect(items()[0]).toBe(t("devices.menu.details"));
});

it("opens a device's details from its one menu and returns focus to it", async () => {
  setup();
  menu("My desktop");
  fireEvent.click(item(t("devices.menu.details")));
  const dialog = screen.getByRole("dialog", { name: "My desktop" });
  expect(within(dialog).getByText(t("devices.row.network.isolated"))).toBeTruthy();
  expect(within(dialog).getByText(t("devices.row.lastOwnerDevice"))).toBeTruthy();
  fireEvent.keyDown(dialog, { key: "Escape" });
  expect(screen.queryByRole("dialog")).toBeNull();
  await waitFor(() => expect(document.activeElement).toBe(screen.getByRole("button", { name: t("devices.menu.deviceActions", { name: "My desktop" }) })));
});

it("never counts a WireGuard-only phone as a device that can keep or receive ownership", () => {
  const owner = snapshot.members[0];
  const phone = { id: "owner-phone", member_id: "owner", name: "Owner iPhone", client_tunnel_address: "10.77.0.9", wireguard_only: true };
  const family = snapshot.members[1];
  const router = { id: "router", member_id: "member", name: "Router", client_tunnel_address: "10.77.0.10", wireguard_only: true };
  const props = setup({
    onWireGuard: vi.fn(),
    snapshot: { ...snapshot, members: [{ ...owner, devices: [...owner.devices, phone] }, { ...family, devices: [router] }] },
  });
  menu("My desktop");
  expect(item(t("devices.menu.revoke", { name: "My desktop" })).disabled).toBe(true);
  closeMenu();
  memberMenu("Owner");
  fireEvent.click(item(t("devices.menu.addWireguardFor", { name: "Owner" })));
  expect(props.onWireGuard).toHaveBeenCalledWith(expect.objectContaining({ id: "owner" }));
  menu("Owner iPhone");
  expect(item(t("devices.menu.revoke", { name: "Owner iPhone" })).disabled).toBe(false);
  closeMenu();
  memberMenu("Family");
  expect(item(t("devices.menu.transfer")).disabled).toBe(true);
  expect(screen.getByText(t("devices.menu.needsManagedDevice"))).toBeTruthy();
  closeMenu();
  expect(screen.getAllByText(t("devices.row.wireguardShort"))).toHaveLength(2);
});
