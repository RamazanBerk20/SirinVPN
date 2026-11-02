import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import { api } from "../../api";
import { JoinFlow } from "./JoinFlow";
import { invitationRejection } from "./InvitationReview";
import { t } from "../../i18n";

vi.mock("../../api", () => ({ api: { previewInvitation: vi.fn(), joinServer: vi.fn() } }));
afterEach(() => { cleanup(); vi.resetAllMocks(); });

const preview = { server_name: "My VPS", host: "vpn.example.com", server_identity_fingerprint: "SHA256:example", expires_at_unix: 1_900_000_000,
  recipient_names: true, creates_member: false, member_name: "Family", device_name: "", access_level: "owner" as const };

it("classifies the backend's refusals separately from failures worth retrying", () => {
  expect(invitationRejection(new Error("the invitation has expired"))).toBe("expired");
  expect(invitationRejection("The invitation has no joins remaining.")).toBe("used");
  expect(invitationRejection(new Error("the invitation signature is invalid"))).toBe("invalid");
  expect(invitationRejection(new Error("the invitation code is invalid"))).toBe("invalid");
  expect(invitationRejection(new Error("connection refused"))).toBeNull();
});

it("replaces Review with Change code when the invitation is refused", async () => {
  vi.mocked(api.previewInvitation).mockRejectedValue(new Error("the invitation has expired"));
  render(<JoinFlow onComplete={vi.fn()} />);
  fireEvent.change(screen.getByRole("textbox"), { target: { value: "sirin1.code" } });
  fireEvent.click(screen.getByRole("button", { name: t("onboarding.join.review") }));
  expect((await screen.findByRole("alert")).textContent?.trim()).toBe(t("devices.join.rejected.expired"));
  expect(screen.queryByRole("button", { name: t("onboarding.join.review") })).toBeNull();
  fireEvent.click(screen.getByRole("button", { name: t("devices.join.changeCode") }));
  expect((screen.getByRole("textbox") as HTMLTextAreaElement).value).toBe("");
  expect(screen.queryByRole("alert")).toBeNull();
});

it("hides an accepted code and says what an Owner invitation grants", async () => {
  vi.mocked(api.previewInvitation).mockResolvedValue(preview);
  render(<JoinFlow onComplete={vi.fn()} />);
  fireEvent.change(screen.getByRole("textbox"), { target: { value: "sirin1.code" } });
  fireEvent.click(screen.getByRole("button", { name: t("onboarding.join.review") }));
  expect(await screen.findByText(t("devices.join.codeAccepted"))).toBeTruthy();
  expect(screen.queryByDisplayValue("sirin1.code")).toBeNull();
  expect(screen.getByText(t("devices.join.ownerDevice", { name: "Family" }))).toBeTruthy();
  expect((screen.getByRole("button", { name: t("onboarding.join.submit") }) as HTMLButtonElement).disabled).toBe(false);
  fireEvent.change(screen.getByLabelText(t("onboarding.invitation.deviceName")), { target: { value: " " } });
  expect((screen.getByRole("button", { name: t("onboarding.join.submit") }) as HTMLButtonElement).disabled).toBe(true);
});
