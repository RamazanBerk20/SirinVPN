import { invoke } from "@tauri-apps/api/core";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { DevicePairsDialog } from "./DevicePairsDialog";
import { DeviceList } from "./DeviceList";
import { t } from "../../i18n";
import type { MembershipSnapshot } from "../../types";

vi.mock("@tauri-apps/api/core", () => ({ invoke: vi.fn(), Channel: vi.fn() }));

beforeEach(() => {
  vi.resetAllMocks();
  vi.mocked(invoke).mockResolvedValue({ members: [], active_invitations: [] });
});
afterEach(cleanup);

const laptop = { id: "laptop", member_id: "family", name: "Laptop", client_tunnel_address: "10.77.0.4" };
const phone = { id: "phone", member_id: "family", name: "Phone", client_tunnel_address: "10.77.0.5" };
// A member's snapshot also lists pairs with devices it cannot see, such as the Owner's NAS.
const snapshot: MembershipSnapshot = {
  active_invitations: [],
  members: [{ id: "family", name: "Family", role: "member", policy: { device_limit: null, expires_at_unix: null, weekly_access: [], invite_members: false,
    add_own_devices: false, manage_own_peer_communication: true, manage_own_port_forwards: false }, devices: [laptop, phone] }],
  device_pairs: [
    { device_id: "laptop", peer_device_id: "phone" },
    { device_id: "nas", peer_device_id: "laptop", one_way: true },
  ],
};

it("adds a pair in the chosen direction and removes only pairs the caller manages", async () => {
  const onSaved = vi.fn().mockResolvedValue(undefined);
  render(<DevicePairsDialog serverId="server" device={laptop} snapshot={snapshot} candidates={[phone]} onClose={vi.fn()} onSaved={onSaved} />);
  expect(screen.getByText(t("devices.pairs.bothWays", { name: "Phone" }))).toBeTruthy();
  expect(screen.getByText(t("devices.pairs.answers", { name: t("devices.pairs.otherDevice") }))).toBeTruthy();
  expect(screen.getAllByRole("button", { name: t("devices.pairs.remove") })).toHaveLength(1);

  // "The other starts" makes the peer the starting device of a one-way pair.
  const [peer, direction] = screen.getAllByRole("combobox") as HTMLSelectElement[];
  expect(peer.value).toBe("phone");
  fireEvent.change(direction, { target: { value: "answers" } });
  fireEvent.click(screen.getByRole("button", { name: t("devices.pairs.save") }));
  await waitFor(() => expect(onSaved).toHaveBeenCalledTimes(1));
  expect(invoke).toHaveBeenCalledWith("set_device_pair", { input: {
    server_id: "server", device_id: "phone", peer_device_id: "laptop", one_way: true,
  } });
  fireEvent.click(screen.getByRole("button", { name: t("devices.pairs.remove") }));
  await waitFor(() => expect(onSaved).toHaveBeenCalledTimes(2));
  expect(invoke).toHaveBeenCalledWith("remove_device_pair", { input: {
    server_id: "server", device_id: "laptop", peer_device_id: "phone",
  } });
});

it("offers pairs with the switch permission and lists them in the device facts", () => {
  const onPairs = vi.fn();
  const base = { snapshot, query: "", accessBusy: null, peerBusy: null, onInvite: vi.fn(), onAccess: vi.fn(),
    onTransfer: vi.fn(), onRename: vi.fn(), onRevoke: vi.fn(), onPeer: vi.fn(), onPairs };
  render(<DeviceList {...base} accessLevel="member" />);
  fireEvent.click(screen.getByRole("button", { name: t("devices.menu.deviceActions", { name: "Laptop" }) }));
  fireEvent.click(screen.getByRole("menuitem", { name: t("devices.menu.pairs") }));
  expect(onPairs).toHaveBeenCalledWith(laptop);
  const label = screen.getAllByText(t("devices.row.facts.pairs"))[0];
  expect(label.nextElementSibling?.textContent).toBe(
    `${t("devices.pairs.bothWays", { name: "Phone" })}; ${t("devices.pairs.answers", { name: t("devices.pairs.otherDevice") })}`,
  );
  expect(screen.getAllByText(t("devices.row.network.paired"))).toHaveLength(2);
  cleanup();
  // Without the permission a member has no device actions at all.
  const restricted = { ...snapshot, members: [{ ...snapshot.members[0], policy: undefined }] };
  render(<DeviceList {...base} snapshot={restricted} accessLevel="member" />);
  expect(screen.queryByRole("button", { name: t("devices.menu.deviceActions", { name: "Laptop" }) })).toBeNull();
});
