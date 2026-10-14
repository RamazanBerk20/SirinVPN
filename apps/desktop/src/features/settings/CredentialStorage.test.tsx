import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import { invoke } from "../../platform";
import { CredentialStorage } from "./CredentialStorage";
import { t } from "../../i18n";
vi.mock("../../platform", () => ({ invoke: vi.fn() }));
afterEach(() => { cleanup(); vi.resetAllMocks(); });
const initial = { supported: true, policy: "secure_store_required", pending_cleanup: 1, profiles: [] };

it("requires explicit fallback consent and waits for native acknowledgement", async () => {
  vi.mocked(invoke).mockResolvedValue(initial);
  render(<CredentialStorage />);
  const allow = await screen.findByRole("button", { name: t("settings.credentials.allowFile") });
  expect(allow.matches(":disabled")).toBe(true);
  fireEvent.click(screen.getByRole("switch", { name: t("settings.credentials.consent") }));
  let complete!: (value: unknown) => void;
  vi.mocked(invoke).mockImplementationOnce(() => new Promise(resolve => { complete = resolve; }));
  fireEvent.click(allow); fireEvent.click(allow);
  expect(invoke).toHaveBeenCalledTimes(2);
  expect(screen.queryByText(t("settings.credentials.policy.fileAllowed"))).toBeNull();
  await act(async () => complete({ ...initial, policy: "allow_private_file" }));
  expect(screen.getByText(t("settings.credentials.policy.fileAllowed"))).toBeTruthy();
});

it("keeps incomplete cleanup actionable after failure and retries", async () => {
  vi.mocked(invoke).mockResolvedValue(initial);
  render(<CredentialStorage />);
  const retry = await screen.findByRole("button", { name: t("settings.credentials.retryCleanup") });
  vi.mocked(invoke).mockRejectedValueOnce("Unlock the system keyring and retry.");
  fireEvent.click(retry);
  expect(await screen.findByRole("alert")).toBeTruthy();
  expect(screen.getByText(t("settings.credentials.pendingCleanup"))).toBeTruthy();
  await waitFor(() => expect(retry.matches(":disabled")).toBe(false));
  vi.mocked(invoke).mockResolvedValueOnce({ ...initial, pending_cleanup: 0 });
  fireEvent.click(retry);
  await waitFor(() => expect(screen.queryByRole("button", { name: t("settings.credentials.retryCleanup") })).toBeNull());
});

it("does not publish an old completion into a reopened screen", async () => {
  let complete!: (value: unknown) => void;
  vi.mocked(invoke).mockImplementationOnce(() => new Promise(resolve => { complete = resolve; }));
  const old = render(<CredentialStorage />);
  old.unmount();
  vi.mocked(invoke).mockResolvedValue({ ...initial, pending_cleanup: 0 });
  render(<CredentialStorage />);
  await screen.findByText(t("settings.credentials.policy.secure"));
  await act(async () => complete({ ...initial, policy: "allow_private_file" }));
  expect(screen.queryByText(t("settings.credentials.policy.fileAllowed"))).toBeNull();
});

it("clears previously available storage when a refresh cannot read native state", async () => {
  vi.mocked(invoke).mockResolvedValue({ ...initial, profiles: [{ server_id: "fixture", name: "Fixture profile",
    storage: { backend: "keyring", protection: "system_secure_store", availability: "available", cleanup_pending: false } }] });
  render(<CredentialStorage />);
  const summary = t("common.separator.pair", { first: t("settings.credentials.protection.keyring"), second: t("settings.credentials.availability.available") });
  expect(await screen.findByText(summary)).toBeTruthy();
  vi.mocked(invoke).mockRejectedValueOnce("Storage status unavailable.");
  fireEvent.click(screen.getByRole("button", { name: t("settings.credentials.refresh") }));
  expect(await screen.findByRole("alert")).toBeTruthy();
  expect(screen.queryByText(summary)).toBeNull();
  expect(screen.getByRole("button", { name: t("common.action.retry") })).toBeTruthy();
});
