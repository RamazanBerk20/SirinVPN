import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import { api } from "../../api";
import { JoinFlow } from "./JoinFlow";
import { invitationRejection } from "./InvitationReview";
import { t } from "../../i18n";
import type { InvitationPreview } from "../../types";

vi.mock("../../api", () => ({ api: { previewInvitation: vi.fn(), joinServer: vi.fn() } }));
afterEach(() => { cleanup(); vi.resetAllMocks(); });

const preview: InvitationPreview = { server_name: "My VPS", host: "vpn.example.com", server_identity_fingerprint: "SHA256:example", expires_at_unix: 1_900_000_000,
  recipient_names: true, creates_member: false, member_name: "Family", device_name: "", access_level: "owner" };

const coded = (code: string) => Object.assign(new Error("refused"), { code, params: {} });

it("classifies the backend's coded refusals separately from failures worth retrying", () => {
  expect(invitationRejection(coded("invitation_expired"))).toBe("expired");
  expect(invitationRejection(coded("invitation_used"))).toBe("used");
  expect(invitationRejection(coded("invitation_invalid"))).toBe("invalid");
  // English text alone is never matched.
  expect(invitationRejection(new Error("the invitation has expired"))).toBeNull();
  expect(invitationRejection(new Error("connection refused"))).toBeNull();
});

it("replaces Review with Change code when the invitation is refused", async () => {
  vi.mocked(api.previewInvitation).mockRejectedValue(coded("invitation_expired"));
  render(<JoinFlow onComplete={vi.fn()} />);
  fireEvent.change(screen.getByRole("textbox"), { target: { value: "sirin1.code" } });
  fireEvent.click(screen.getByRole("button", { name: t("onboarding.join.review") }));
  expect((await screen.findByRole("alert")).textContent?.trim()).toBe(t("devices.join.rejected.expired"));
  expect(screen.queryByRole("button", { name: t("onboarding.join.review") })).toBeNull();
  fireEvent.click(screen.getByRole("button", { name: t("devices.join.changeCode") }));
  expect((screen.getByRole("textbox") as HTMLTextAreaElement).value).toBe("");
  expect(screen.queryByRole("alert")).toBeNull();
});

it("hides an accepted code and says what an Owner join code grants", async () => {
  vi.mocked(api.previewInvitation).mockResolvedValue(preview);
  render(<JoinFlow onComplete={vi.fn()} />);
  fireEvent.change(screen.getByRole("textbox"), { target: { value: "sirin1.code" } });
  fireEvent.click(screen.getByRole("button", { name: t("onboarding.join.review") }));
  expect(await screen.findByText(t("devices.join.codeAccepted"))).toBeTruthy();
  expect(screen.queryByDisplayValue("sirin1.code")).toBeNull();
  expect(screen.getByText(t("devices.join.ownerDevice", { name: "Family" }))).toBeTruthy();
  // No default device name: nobody is named after a placeholder.
  const submit = screen.getByRole("button", { name: t("onboarding.join.submit") }) as HTMLButtonElement;
  expect(submit.disabled).toBe(true);
  fireEvent.change(screen.getByTestId("join-device-name"), { target: { value: "Pixel 9" } });
  expect(submit.disabled).toBe(false);
  fireEvent.change(screen.getByTestId("join-device-name"), { target: { value: " " } });
  expect(submit.disabled).toBe(true);
});

async function review(value: typeof preview) {
  vi.mocked(api.previewInvitation).mockResolvedValue(value);
  vi.mocked(api.joinServer).mockResolvedValue({} as never);
  render(<JoinFlow onComplete={vi.fn()} />);
  fireEvent.change(screen.getByRole("textbox"), { target: { value: "sirin1.code" } });
  fireEvent.click(screen.getByRole("button", { name: t("onboarding.join.review") }));
  await screen.findByText(t("devices.join.codeAccepted"));
}

it("asks someone new for their own name only when the code doesn't carry one", async () => {
  await review({ ...preview, creates_member: true, member_name: "Invited member", access_level: "member" });
  fireEvent.change(screen.getByTestId("join-person-name"), { target: { value: "Ayşe" } });
  fireEvent.change(screen.getByTestId("join-device-name"), { target: { value: "Pixel 9" } });
  fireEvent.click(screen.getByRole("button", { name: t("onboarding.join.submit") }));
  expect(api.joinServer).toHaveBeenCalledWith("sirin1.code", { member_name: "Ayşe", device_name: "Pixel 9" });
});

it("keeps the name the inviter typed and asks only for the device's", async () => {
  await review({ ...preview, creates_member: true, member_name: "Ayşe", access_level: "member", member_name_fixed: true });
  expect(screen.queryByTestId("join-person-name")).toBeNull();
  expect(screen.getByTestId("join-person").textContent).toContain("Ayşe");
  fireEvent.change(screen.getByTestId("join-device-name"), { target: { value: "Pixel 9" } });
  fireEvent.click(screen.getByRole("button", { name: t("onboarding.join.submit") }));
  expect(api.joinServer).toHaveBeenCalledWith("sirin1.code", { device_name: "Pixel 9" });
});

it("shows both names fixed by an older server and sends none", async () => {
  await review({ ...preview, recipient_names: false, creates_member: true, member_name: "Ayşe", device_name: "Ayşe’s phone", access_level: "admin" });
  expect(screen.queryByTestId("join-device-name")).toBeNull();
  expect(screen.getByTestId("join-role").textContent).toContain(t("common.role.admin"));
  fireEvent.click(screen.getByRole("button", { name: t("onboarding.join.submit") }));
  expect(api.joinServer).toHaveBeenCalledWith("sirin1.code", {});
});
