import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import { api } from "../../api";
import { MemberPolicyDialog } from "./MemberPolicyDialog";
import { t } from "../../i18n";

vi.mock("../../api", () => ({ api: { updateMemberPolicy: vi.fn() } }));
afterEach(() => { cleanup(); vi.resetAllMocks(); });

const member = { id: "family", name: "Family", role: "member" as const, devices: [] };
const save = () => screen.getByRole("button", { name: t("devices.policy.save") }) as HTMLButtonElement;

it("keeps Save off while a field is invalid and warns about a past expiry", async () => {
  vi.mocked(api.updateMemberPolicy).mockResolvedValue(undefined as never);
  const onSaved = vi.fn().mockResolvedValue(undefined), onClose = vi.fn();
  render(<MemberPolicyDialog serverId="server" member={member} onClose={onClose} onSaved={onSaved} />);
  expect(screen.getByText(t("devices.policy.cancelsInvitations", { name: "Family" }))).toBeTruthy();
  expect(screen.getByText(t("devices.policy.permissions"))).toBeTruthy();
  fireEvent.change(screen.getByLabelText(new RegExp(t("devices.policy.deviceLimit"))), { target: { value: "0" } });
  expect(screen.getByText(t("devices.policy.error.limit"))).toBeTruthy();
  expect(save().disabled).toBe(true);
  fireEvent.change(screen.getByLabelText(new RegExp(t("devices.policy.deviceLimit"))), { target: { value: "3" } });
  fireEvent.change(screen.getByLabelText(new RegExp(t("devices.policy.expires"))), { target: { value: "2020-01-01T12:00" } });
  expect(screen.getByText(t("devices.policy.expiresPast"))).toBeTruthy();
  expect(save().disabled).toBe(false);
  fireEvent.click(save());
  await waitFor(() => expect(onClose).toHaveBeenCalled());
  expect(api.updateMemberPolicy).toHaveBeenCalledWith("server", "family", expect.objectContaining({
    device_limit: 3, expires_at_unix: new Date("2020-01-01T12:00").getTime() / 1000,
  }));
});

it("enters a weekly interval in local time with one card per interval", () => {
  render(<MemberPolicyDialog serverId="server" member={member} onClose={vi.fn()} onSaved={vi.fn()} />);
  expect(screen.getByText(t("devices.schedule.allWeek"))).toBeTruthy();
  fireEvent.click(screen.getByRole("button", { name: t("devices.schedule.add") }));
  expect(screen.queryByText(t("devices.schedule.allWeek"))).toBeNull();
  expect(screen.getByRole("group", { name: t("devices.schedule.interval", { number: 1 }) })).toBeTruthy();
  const [start, end] = screen.getAllByLabelText(/^(Start|End)$/) as HTMLInputElement[];
  fireEvent.change(end, { target: { value: start.value } });
  expect(screen.getByText(t("devices.schedule.sameTime", { number: 1 }))).toBeTruthy();
  expect(save().disabled).toBe(true);
});
