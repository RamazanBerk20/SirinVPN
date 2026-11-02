import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import { ActiveInvitations } from "./ActiveInvitations";
import type { MembershipSnapshot } from "../../types";
import { t } from "../../i18n";
import { formatExpiry } from "../../lib/errors";

afterEach(cleanup);
const row = (role: "owner" | "admin" | "member", uses: string) =>
  t("devices.invitations.row", { role: t(`common.role.${role}`), uses, date: formatExpiry(1_900_000_000) });
const reusable = t("devices.invitations.usesLeft", { left: 7, max: 10 });
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

it("shows the role, how many uses are left and the expiry, and cancels from the row", async () => {
  const onCancel = vi.fn().mockResolvedValue(undefined);
  const { container } = render(<ActiveInvitations snapshot={snapshot} accessLevel="owner" onCancel={onCancel} />);
  expect(screen.getByText(t("devices.invitations.newMember"))).toBeTruthy();
  expect(container.querySelector("small")?.textContent).toBe(row("admin", reusable));
  expect(container.textContent).not.toMatch(/Recipient chooses|Phone|joins remaining/);
  fireEvent.click(screen.getByRole("button", { name: t("devices.invitations.cancel") }));
  await waitFor(() => expect(onCancel).toHaveBeenCalledWith("invite"));
});

it("says single use for a one-time code", () => {
  const single = { ...snapshot, active_invitations: [{ ...snapshot.active_invitations[0], max_uses: 1, uses_remaining: 1 }] };
  const { container } = render(<ActiveInvitations snapshot={single} accessLevel="owner" onCancel={vi.fn()} />);
  expect(container.querySelector("small")?.textContent).toBe(row("admin", t("devices.invitations.singleUse")));
});

it.each(["owner", "admin", "member"] as const)(
  "titles a device code after the existing %s member and uses their role",
  (target_member_id) => {
    const data = { ...snapshot, active_invitations: [{ ...snapshot.active_invitations[0], target_member_id }] };
    const { container } = render(<ActiveInvitations snapshot={data} accessLevel="owner" onCancel={vi.fn()} />);
    const name = snapshot.members.find((member) => member.id === target_member_id)!.name;
    expect(screen.getByText(t("devices.invitations.newDevice", { name }))).toBeTruthy();
    expect(container.querySelector("small")?.textContent).toBe(row(target_member_id, reusable));
  },
);

it("shows a failed cancellation under its invitation with Try again", async () => {
  const onCancel = vi.fn().mockRejectedValueOnce(new Error("Couldn’t cancel the invitation.")).mockResolvedValue(undefined);
  render(<ActiveInvitations snapshot={snapshot} accessLevel="owner" onCancel={onCancel} />);
  fireEvent.click(screen.getByRole("button", { name: t("devices.invitations.cancel") }));
  expect((await screen.findByRole("alert")).textContent).toContain("Couldn’t cancel the invitation.");
  fireEvent.click(screen.getByRole("button", { name: t("common.action.retry") }));
  await waitFor(() => expect(onCancel).toHaveBeenCalledTimes(2));
  await waitFor(() => expect(screen.queryByRole("alert")).toBeNull());
});

it("preserves the Admin cancellation restriction for privileged invitations", () => {
  render(<ActiveInvitations snapshot={snapshot} accessLevel="admin" onCancel={vi.fn()} />);
  expect(screen.queryByRole("button", { name: t("devices.invitations.cancel") })).toBeNull();
});

it("renders nothing without invitations instead of an empty heading", () => {
  const { container } = render(<ActiveInvitations snapshot={{ ...snapshot, active_invitations: [] }} accessLevel="owner" onCancel={vi.fn()} />);
  expect(container.textContent).toBe("");
});
