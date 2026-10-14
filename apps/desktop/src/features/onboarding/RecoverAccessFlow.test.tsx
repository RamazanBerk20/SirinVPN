import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { api } from "../../api";
import { RecoverAccessFlow } from "./RecoverAccessFlow";
import type { RecoveryPreview, ServerProfile } from "../../types";
import { t } from "../../i18n";

vi.mock("../../api", () => ({ api: { previewRecoveryKey: vi.fn(), recoverOwnerAccess: vi.fn() } }));
vi.mock("@tauri-apps/plugin-dialog", () => ({ open: vi.fn() }));
const preview: RecoveryPreview = { existing_profile: true, preview: { server_id: "a", server_name: "My VPS", host: "vps.example", recovery_id: "recovery", server_identity_fingerprint: "test-pin" } };
beforeEach(() => { vi.resetAllMocks(); vi.mocked(api.previewRecoveryKey).mockResolvedValue(preview); vi.mocked(api.recoverOwnerAccess).mockResolvedValue({ id: "a" } as ServerProfile); });
afterEach(cleanup);

it("requires both Owner revocation and local replacement confirmation before recovery", async () => {
  const completed = vi.fn().mockResolvedValue(undefined);
  render(<RecoverAccessFlow onComplete={completed} />);
  fireEvent.change(screen.getByLabelText(t("onboarding.recover.key")), { target: { value: "sirr1.test" } });
  fireEvent.click(screen.getByRole("button", { name: t("onboarding.recover.review") }));
  await screen.findByText("My VPS");
  const submit = screen.getByRole("button", { name: t("onboarding.recover.submit") }) as HTMLButtonElement;
  expect(submit.disabled).toBe(true);
  fireEvent.click(screen.getByRole("checkbox", { name: t("onboarding.recover.confirmRevoke") }));
  expect(submit.disabled).toBe(true);
  fireEvent.submit(submit.closest("form")!);
  expect(api.recoverOwnerAccess).not.toHaveBeenCalled();
  await waitFor(() => expect(submit.textContent).toBe(t("onboarding.recover.submit")));
  fireEvent.click(screen.getByRole("checkbox", { name: t("onboarding.recover.replaceProfile", { name: "My VPS" }) }));
  fireEvent.click(submit);
  await waitFor(() => expect(completed).toHaveBeenCalled());
  expect(api.recoverOwnerAccess).toHaveBeenCalledWith("sirr1.test", t("onboarding.recover.defaultDeviceName"), true, true);
});

it("ignores a late preview after the recovery key changes", async () => {
  let resolve!: (value: RecoveryPreview) => void;
  vi.mocked(api.previewRecoveryKey).mockImplementation(() => new Promise((done) => { resolve = done; }));
  render(<RecoverAccessFlow onComplete={vi.fn()} />);
  fireEvent.change(screen.getByLabelText(t("onboarding.recover.key")), { target: { value: "sirr1.first" } });
  fireEvent.click(screen.getByRole("button", { name: t("onboarding.recover.review") }));
  fireEvent.change(screen.getByLabelText(t("onboarding.recover.key")), { target: { value: "sirr1.changed" } });
  await act(async () => resolve(preview));
  expect(screen.queryByText("My VPS")).toBeNull();
  expect(api.recoverOwnerAccess).not.toHaveBeenCalled();
});
