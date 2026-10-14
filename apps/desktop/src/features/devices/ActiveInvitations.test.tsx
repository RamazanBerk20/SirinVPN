import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import { ActiveInvitations } from "./ActiveInvitations";
import type { MembershipSnapshot } from "../../types";
import { t } from "../../i18n";
import { formatExpiry } from "../../lib/errors";

afterEach(cleanup);
const row = (role: "owner" | "admin" | "member") =>
  t("devices.invitations.row", { role: t(`common.role.${role}`), date: formatExpiry(1_900_000_000) });
const snapshot: MembershipSnapshot = {
  members: [
    { id: "admin", name: "Admin", role: "member", administrator: true, devices: [] },
    { id: "owner", name: "Owner", role: "owner", devices: [] },
    { id: "member", name: "Member", role: "member", administrator: false, devices: [] },
  ],
  active_invitations: [{
    id: "invite", member_name: "Guest", device_name: "Phone", recipient_names: true,
    administrator: true, expires_at_unix: 1_900_000_000, max_uses: 10, uses_remaining: 7,
  }],
};

it("shows only role and expiry, and keeps cancellation available", () => {
  const onCancel = vi.fn().mockResolvedValue(undefined);
  const { container } = render(<ActiveInvitations snapshot={snapshot} accessLevel="owner" onCancel={onCancel} />);
  expect(container.querySelector("small")?.textContent).toBe(row("admin"));
  expect(container.textContent).not.toMatch(/Recipient chooses|Phone|joins remaining/);
  fireEvent.click(screen.getByText(t("devices.invitations.title")));
  fireEvent.click(screen.getByRole("button", { name: t("common.action.cancel") }));
  expect(onCancel).toHaveBeenCalledWith("invite");
});

it.each(["owner", "admin", "member"] as const)(
  "uses the existing %s member's role for an additional device",
  (target_member_id) => {
    const data = { ...snapshot, active_invitations: [{ ...snapshot.active_invitations[0], target_member_id }] };
    const { container } = render(<ActiveInvitations snapshot={data} accessLevel="owner" onCancel={vi.fn()} />);
    expect(container.querySelector("small")?.textContent).toBe(row(target_member_id));
  },
);

it("preserves the Admin cancellation restriction for privileged invitations", () => {
  render(<ActiveInvitations snapshot={snapshot} accessLevel="admin" onCancel={vi.fn()} />);
  fireEvent.click(screen.getByText(t("devices.invitations.title")));
  expect(screen.queryByRole("button", { name: t("common.action.cancel") })).toBeNull();
});
