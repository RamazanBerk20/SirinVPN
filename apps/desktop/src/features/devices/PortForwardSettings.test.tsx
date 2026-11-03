import { cleanup, render, screen, waitFor } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import { api } from "../../api";
import { PortForwardSettings } from "./PortForwardSettings";
import { clearMembershipCache } from "./membershipCache";
import { t } from "../../i18n";
import type { MembershipSnapshot } from "../../types";

vi.mock("../../api", () => ({ api: { membership: vi.fn(), serverConfiguration: vi.fn() } }));
afterEach(() => { cleanup(); clearMembershipCache(); vi.resetAllMocks(); });

const member = (forwards: boolean): MembershipSnapshot => ({
  active_invitations: [],
  members: [{ id: "self", name: "Me", role: "member", devices: [{ id: "this", member_id: "self", name: "Laptop", client_tunnel_address: "10.77.0.2" }],
    policy: { device_limit: null, expires_at_unix: null, weekly_access: [], invite_members: false, add_own_devices: false,
      manage_own_peer_communication: false, manage_own_port_forwards: forwards } }],
});
const show = () => render(<PortForwardSettings profile={{ id: "server", name: "VPS", device_id: "this" }} connected accessLevel="member" onAccessChanged={vi.fn()} />);

it("shows a Member the card only when their policy allows forwarding", async () => {
  vi.mocked(api.serverConfiguration).mockResolvedValue({ port_forwarding_enabled: true });
  vi.mocked(api.membership).mockResolvedValue(member(false));
  show();
  await waitFor(() => expect(api.membership).toHaveBeenCalled());
  // Let the loaded list render: the card stays away after loading too, not only while it loads.
  await new Promise((resolve) => setTimeout(resolve, 20));
  expect(screen.queryByRole("region", { name: t("devices.ports.title") })).toBeNull();
  cleanup(); clearMembershipCache();
  vi.mocked(api.membership).mockResolvedValue(member(true));
  show();
  expect(await screen.findByRole("region", { name: t("devices.ports.title") })).toBeTruthy();
});
