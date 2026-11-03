import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import { api } from "../../api";
import { AccessPanel } from "./AccessPanel";
import { clearMembershipCache } from "./membershipCache";
import { t } from "../../i18n";
import type { MemberPolicy, MembershipSnapshot } from "../../types";

vi.mock("../../api", () => ({ api: { membership: vi.fn(), serverConfiguration: vi.fn() } }));
afterEach(() => { cleanup(); clearMembershipCache(); vi.resetAllMocks(); });

const policy = (invite_members: boolean): MemberPolicy => ({ device_limit: null, expires_at_unix: null, weekly_access: [], invite_members,
  add_own_devices: true, manage_own_peer_communication: false, manage_own_port_forwards: false });
const own = (role: "owner" | "member", invite = false): MembershipSnapshot => ({
  active_invitations: [],
  members: [{ id: "self", name: "Me", role, policy: policy(invite), devices: [{ id: "this", member_id: "self", name: "Laptop", client_tunnel_address: "10.77.0.2" }] }],
});
const show = (accessLevel: "owner" | "member") => render(<AccessPanel profile={{ id: "server", name: "VPS", device_id: "this" }}
  connected accessLevel={accessLevel} onAccessChanged={vi.fn()} />);

it("hides Invite member from a member who may never invite, and shows it once allowed", async () => {
  vi.mocked(api.serverConfiguration).mockResolvedValue({});
  vi.mocked(api.membership).mockResolvedValue(own("member"));
  show("member");
  await screen.findByText("Laptop");
  // With only their own devices to add, the one Add device button does that directly.
  expect(screen.getByRole("button", { name: t("devices.panel.add") }).getAttribute("aria-haspopup")).toBeNull();
  cleanup(); clearMembershipCache();
  vi.mocked(api.membership).mockResolvedValue(own("member", true));
  show("member");
  const add = await screen.findByRole("button", { name: t("devices.panel.add") });
  await waitFor(() => expect((add as HTMLButtonElement).disabled).toBe(false));
  fireEvent.click(add);
  expect(screen.getAllByRole("menuitem").map((item) => item.textContent)).toEqual([t("devices.panel.addMine"), t("devices.panel.invite")]);
});

it("offers a next step when this is the only device, and retries a failed load in place", async () => {
  vi.mocked(api.serverConfiguration).mockResolvedValue({});
  vi.mocked(api.membership).mockRejectedValueOnce(new Error("Connection reset")).mockResolvedValue(own("owner"));
  show("owner");
  expect((await screen.findByRole("alert")).textContent).toContain("Connection reset");
  fireEvent.click(screen.getByRole("button", { name: t("common.action.retry") }));
  expect(await screen.findByText(t("devices.panel.aloneTitle"))).toBeTruthy();
  // One device: no search field to filter it.
  expect(screen.queryByRole("searchbox")).toBeNull();
});

it("uses the verified list's role right after ownership moved away from this device", async () => {
  vi.mocked(api.serverConfiguration).mockResolvedValue({});
  const transferred = own("member");
  transferred.members[0].administrator = true;
  vi.mocked(api.membership).mockResolvedValue(transferred);
  show("owner");
  await screen.findByText("Laptop");
  // An admin can't change their own role or reach the Owner-only menu items.
  expect(screen.queryByRole("button", { name: t("devices.menu.memberActions", { name: "Me" }) })).toBeNull();
});
