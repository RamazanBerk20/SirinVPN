import { afterEach, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
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
  expect(Boolean(screen.queryByText(t("common.noun.thisDevice")))).toBe(currentDeviceId === "desktop");
});

it("shows the VPN address and role as one subtitle", () => {
  setup({ query: "10.77.0.3" });
  const subtitle = screen.getByRole("button", { name: /^Android phone/ }).querySelector("small")!;
  expect(subtitle.textContent).toBe(
    t("devices.row.subtitle", { address: "10.77.0.3", role: t("common.role.member") }).replace(/<\/?address>/g, ""),
  );
  expect(subtitle.querySelector(".mono")?.textContent).toBe("10.77.0.3");
});

it("keeps filtered overflow actions bound to the correct device and member", () => {
  const props = setup({ query: "10.77.0.3" });
  expect(screen.queryByText("My desktop")).toBeNull();
  menu("Android phone");
  fireEvent.click(screen.getByRole("menuitem", { name: t("devices.menu.rename") }));
  menu("Android phone");
  fireEvent.click(
    screen.getByRole("menuitem", { name: t("devices.menu.allowMutual") }),
  );
  menu("Android phone");
  fireEvent.click(
    screen.getByRole("menuitem", { name: t("devices.menu.addDeviceFor", { name: "Family" }) }),
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
        name: t("devices.menu.revoke", { name: "My desktop" }),
      }) as HTMLButtonElement
    ).disabled,
  ).toBe(true);
  expect(
    screen.getAllByText(t("devices.row.lastOwnerDevice"))[0],
  ).toBeTruthy();
  fireEvent.keyDown(screen.getByRole("menu"), { key: "Escape" });
  expect(document.activeElement).toBe(
    screen.getByRole("button", { name: t("devices.menu.deviceActions", { name: "My desktop" }) }),
  );
  menu("Android phone");
  expect(
    (screen.getByRole("menuitem", { name: t("devices.menu.makeAdmin") }) as HTMLButtonElement)
      .disabled,
  ).toBe(true);
  expect(
    (
      screen.getByRole("menuitem", {
        name: t("devices.menu.transfer"),
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
    screen.queryByRole("button", { name: t("devices.menu.deviceActions", { name: "My desktop" }) }),
  ).toBeNull();
  expect(
    screen.queryByRole("button", { name: t("devices.menu.deviceActions", { name: "Admin laptop" }) }),
  ).toBeNull();
  expect(screen.getByText(t("devices.row.activity.unknown"))).toBeTruthy();
  expect(screen.getByText(t("devices.row.activity.recent"))).toBeTruthy();
  menu("Android phone");
  expect(screen.queryByRole("menuitem", { name: t("devices.menu.makeAdmin") })).toBeNull();
  fireEvent.click(
    screen.getByRole("menuitem", { name: t("devices.menu.revoke", { name: "Android phone" }) }),
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
  expect(screen.queryByRole("menuitem", { name: t("devices.menu.suspend") })).toBeNull();
  fireEvent.keyDown(screen.getByRole("menu"), { key: "Escape" });
  menu("Android phone");
  fireEvent.click(screen.getByRole("menuitem", { name: t("devices.menu.suspend") }));
  expect(props.onMemberSuspension).toHaveBeenCalledWith(snapshot.members[1]);
  menu("Android phone");
  fireEvent.click(
    screen.getByRole("menuitem", { name: t("devices.menu.revokeAll") }),
  );
  expect(props.onRevokeMemberDevices).toHaveBeenCalledWith(snapshot.members[1]);
  cleanup();
  setup();
  menu("Android phone");
  expect(screen.queryByRole("menuitem", { name: t("devices.menu.suspend") })).toBeNull();
});

it("shows suspension over stale activity and prevents enrollment and ownership transfer", () => {
  const suspended = { ...snapshot.members[1], suspended: true };
  const props = setup({
    memberLifecycleAvailable: true,
    onMemberSuspension: vi.fn(),
    snapshot: { ...snapshot, members: [snapshot.members[0], suspended] },
  });
  expect(screen.getByText(t("devices.row.activity.suspended"))).toBeTruthy();
  expect(screen.queryByText(t("devices.row.activity.recent"))).toBeNull();
  menu("Android phone");
  for (const name of [t("devices.menu.addDeviceFor", { name: "Family" }), t("devices.menu.transfer")]) {
    expect(
      (
        screen.getByRole("menuitem", { name }) as HTMLButtonElement
      ).disabled,
    ).toBe(true);
  }
  fireEvent.click(screen.getByRole("menuitem", { name: t("devices.menu.reactivate") }));
  expect(props.onMemberSuspension).toHaveBeenCalledWith(suspended);
  expect(
    screen.queryByRole("button", { name: t("devices.row.transferTo", { name: "Family" }) }),
  ).toBeNull();
});

it("restores expanded details in the same update that dismisses the menu", async () => {
  setup();
  const summary = screen.getByRole("button", { name: /^My desktop/ });
  fireEvent.click(summary);
  menu("My desktop");
  const details = document.getElementById(summary.getAttribute("aria-controls")!)!;
  expect(details.hasAttribute("inert")).toBe(true);
  // Dispatch outside act() so React schedules the dismissal as in a browser,
  // and record the details' state when the menu first leaves the DOM.
  const env = globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean };
  const actEnvironment = env.IS_REACT_ACT_ENVIRONMENT;
  env.IS_REACT_ACT_ENVIRONMENT = false;
  let inertWhenClosed: boolean;
  try {
    inertWhenClosed = await new Promise<boolean>((resolve) => {
      const observer = new MutationObserver(() => {
        if (document.querySelector('[role="menu"]')) return;
        observer.disconnect();
        resolve(details.hasAttribute("inert"));
      });
      observer.observe(document.body, { childList: true, subtree: true });
      document
        .querySelector(".action-menu-backdrop")!
        .dispatchEvent(new MouseEvent("pointerdown", { bubbles: true, cancelable: true }));
    });
    await new Promise((resolve) => setTimeout(resolve));
  } finally {
    env.IS_REACT_ACT_ENVIRONMENT = actEnvironment;
  }
  expect(inertWhenClosed).toBe(false);
  expect(details.hasAttribute("inert")).toBe(false);
  expect(document.activeElement).toBe(
    screen.getByRole("button", { name: "Actions for My desktop" }),
  );
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
  expect((screen.getByRole("menuitem", { name: t("devices.menu.revoke", { name: "My desktop" }) }) as HTMLButtonElement).disabled).toBe(true);
  fireEvent.click(screen.getByRole("menuitem", { name: t("devices.menu.addWireguardFor", { name: "Owner" }) }));
  expect(props.onWireGuard).toHaveBeenCalledWith(expect.objectContaining({ id: "owner" }));
  menu("Owner iPhone");
  expect((screen.getByRole("menuitem", { name: t("devices.menu.revoke", { name: "Owner iPhone" }) }) as HTMLButtonElement).disabled).toBe(false);
  fireEvent.keyDown(screen.getByRole("menu"), { key: "Escape" });
  menu("Router");
  expect((screen.getByRole("menuitem", { name: t("devices.menu.transfer") }) as HTMLButtonElement).disabled).toBe(true);
  fireEvent.keyDown(screen.getByRole("menu"), { key: "Escape" });
  expect(screen.getAllByText(t("devices.row.wireguardOnly"))).toHaveLength(2);
});
