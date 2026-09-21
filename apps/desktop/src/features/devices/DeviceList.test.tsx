import { afterEach, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { DeviceList } from "./DeviceList";
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
  fireEvent.click(screen.getByRole("button", { name: `Actions for ${name}` }));
}

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
  const row = screen.getByRole("button", { name: /^Owner device/ });
  fireEvent.click(row);
  expect(screen.getAllByText("Owner device", { exact: true })).toHaveLength(1);
  expect(screen.queryByText("My computer")).toBeNull();
  expect(screen.queryByText("My Android device")).toBeNull();
  expect(screen.queryByText("Saved device name")).toBeNull();
  expect(screen.queryByText("Access group")).toBeNull();
  expect(Boolean(screen.queryByText("This device"))).toBe(currentDeviceId === "desktop");
});

it("keeps filtered overflow actions bound to the correct device and member", () => {
  const props = setup({ query: "10.77.0.3" });
  expect(screen.queryByText("My desktop")).toBeNull();
  menu("Android phone");
  fireEvent.click(screen.getByRole("menuitem", { name: "Rename device" }));
  menu("Android phone");
  fireEvent.click(
    screen.getByRole("menuitem", { name: "Enable mutual device access" }),
  );
  menu("Android phone");
  fireEvent.click(
    screen.getByRole("menuitem", { name: "Add device for Family" }),
  );
  expect(props.onRename).toHaveBeenCalledWith("phone", "Android phone");
  expect(props.onPeer).toHaveBeenCalledWith("phone", "Android phone", false);
  expect(props.onInvite).toHaveBeenCalledWith(snapshot.members[1]);
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
  expect(
    (
      screen.getByRole("menuitem", {
        name: /Revoke My desktop/,
      }) as HTMLButtonElement
    ).disabled,
  ).toBe(true);
  expect(
    screen.getAllByText("The last Owner device cannot be revoked.")[0],
  ).toBeTruthy();
  fireEvent.keyDown(screen.getByRole("menu"), { key: "Escape" });
  expect(document.activeElement).toBe(
    screen.getByRole("button", { name: "Actions for My desktop" }),
  );
  menu("Android phone");
  expect(
    (screen.getByRole("menuitem", { name: /Make Admin/ }) as HTMLButtonElement)
      .disabled,
  ).toBe(true);
  expect(
    (
      screen.getByRole("menuitem", {
        name: /Transfer ownership/,
      }) as HTMLButtonElement
    ).disabled,
  ).toBe(true);
});
it("limits Admin controls and states unknown activity directly in the row", () => {
  const props = setup({
    accessLevel: "admin",
    currentDeviceId: "admin-device",
  });
  expect(
    screen.queryByRole("button", { name: "Actions for My desktop" }),
  ).toBeNull();
  expect(
    screen.queryByRole("button", { name: "Actions for Admin laptop" }),
  ).toBeNull();
  expect(screen.getByText("Activity unknown")).toBeTruthy();
  expect(screen.getByText("Recently active")).toBeTruthy();
  menu("Android phone");
  expect(screen.queryByRole("menuitem", { name: "Make Admin" })).toBeNull();
  fireEvent.click(
    screen.getByRole("menuitem", { name: "Revoke Android phone" }),
  );
  expect(props.onRevoke).toHaveBeenCalledWith("phone", "Android phone");
});

it("offers member actions only with server support and never on the Owner", () => {
  const props = setup({
    memberLifecycleAvailable: true,
    onMemberSuspension: vi.fn(),
    onRevokeMemberDevices: vi.fn(),
  });
  menu("My desktop");
  expect(screen.queryByRole("menuitem", { name: "Suspend member" })).toBeNull();
  fireEvent.keyDown(screen.getByRole("menu"), { key: "Escape" });
  menu("Android phone");
  fireEvent.click(screen.getByRole("menuitem", { name: "Suspend member" }));
  expect(props.onMemberSuspension).toHaveBeenCalledWith(snapshot.members[1]);
  menu("Android phone");
  fireEvent.click(
    screen.getByRole("menuitem", { name: "Revoke all member devices" }),
  );
  expect(props.onRevokeMemberDevices).toHaveBeenCalledWith(snapshot.members[1]);
  cleanup();
  setup();
  menu("Android phone");
  expect(screen.queryByRole("menuitem", { name: "Suspend member" })).toBeNull();
});

it("shows suspension over stale activity and prevents enrollment and ownership transfer", () => {
  const suspended = { ...snapshot.members[1], suspended: true };
  const props = setup({
    memberLifecycleAvailable: true,
    onMemberSuspension: vi.fn(),
    snapshot: { ...snapshot, members: [snapshot.members[0], suspended] },
  });
  expect(screen.getByText("Suspended")).toBeTruthy();
  expect(screen.queryByText("Recently active")).toBeNull();
  menu("Android phone");
  for (const name of ["Add device for Family", "Transfer ownership"]) {
    expect(
      (
        screen.getByRole("menuitem", {
          name: new RegExp(`^${name}`),
        }) as HTMLButtonElement
      ).disabled,
    ).toBe(true);
  }
  fireEvent.click(screen.getByRole("menuitem", { name: "Reactivate member" }));
  expect(props.onMemberSuspension).toHaveBeenCalledWith(suspended);
  expect(
    screen.queryByRole("button", { name: "Review transfer to Family" }),
  ).toBeNull();
});
