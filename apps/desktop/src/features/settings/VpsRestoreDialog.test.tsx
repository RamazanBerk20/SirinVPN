import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { api } from "../../api";
import { open } from "../../lib/nativeDialog";
import type { ServerProfile, ServerRestoreResult } from "../../types";
import { VpsRestoreDialog } from "./VpsRestoreDialog";
import { t } from "../../i18n";

vi.mock("../../api", () => ({ api: {
  getSshLogin: vi.fn(), saveSshLogin: vi.fn(), forgetSshLogin: vi.fn(), inspectSshHost: vi.fn(), trustSshHost: vi.fn(), restoreVpsBackup: vi.fn(),
} }));
vi.mock("../../lib/nativeDialog", () => ({ open: vi.fn() }));
const profile = { id: "a", name: "My VPS", endpoint: { host: "vps.example" }, role: "owner" } as ServerProfile;
const password = "correct horse battery";

beforeEach(() => {
  vi.resetAllMocks();
  vi.mocked(api.getSshLogin).mockResolvedValue(null);
  vi.mocked(api.saveSshLogin).mockResolvedValue({ username: "root", ssh_port: 22, authentication: "agent", private_key_path: null });
  vi.mocked(api.inspectSshHost).mockResolvedValue({ fingerprint: `SHA256:${"A".repeat(43)}`, status: "trusted" });
  vi.mocked(open).mockResolvedValue("/backups/my-vps.sirinvpn-server-backup");
});
afterEach(cleanup);

async function fill() {
  const completed = vi.fn().mockResolvedValue(undefined);
  render(<VpsRestoreDialog profile={profile} open onOpenChange={vi.fn()} disconnected onCompleted={completed} />);
  const agent = await screen.findByRole("button", { name: t("ssh.auth.agent") });
  await waitFor(() => expect(agent.matches(":disabled")).toBe(false));
  fireEvent.click(agent);
  fireEvent.click(screen.getByRole("button", { name: t("vps.common.chooseFile") }));
  await screen.findByDisplayValue("/backups/my-vps.sirinvpn-server-backup");
  fireEvent.change(screen.getByLabelText(t("vps.common.backupPassword")), { target: { value: password } });
  fireEvent.click(screen.getByRole("button", { name: t("vps.restore.review") }));
  return completed;
}

it("states what the restore replaces and changes nothing until the final button", async () => {
  vi.mocked(api.restoreVpsBackup).mockResolvedValue({ profile: { endpoint: { host: "vps.example" } }, artifact_sha256: "b".repeat(64), events: [] } as unknown as ServerRestoreResult);
  const completed = await fill();
  await screen.findByRole("heading", { name: t("vps.restore.reviewTitle") });
  expect(screen.getByText(t("vps.restore.consequence.access"))).toBeTruthy();
  expect(api.restoreVpsBackup).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole("button", { name: t("vps.restore.action") }));
  await screen.findByText(t("vps.restore.done"));
  expect(api.restoreVpsBackup).toHaveBeenCalledWith(expect.objectContaining({ backup_password: password, host: "vps.example", confirmed: true }));
  expect(completed).toHaveBeenCalledOnce();
});

it("keeps the entered backup password unless the file rejected it", async () => {
  vi.mocked(api.restoreVpsBackup).mockRejectedValueOnce(new Error("SSH connection timed out."));
  await fill();
  fireEvent.click(await screen.findByRole("button", { name: t("vps.restore.action") }));
  await screen.findByText("SSH connection timed out.", { exact: false });
  expect((screen.getByLabelText(t("vps.common.backupPassword")) as HTMLInputElement).value).toBe(password);
  vi.mocked(api.restoreVpsBackup).mockRejectedValueOnce(new Error("the backup password is incorrect or the file was modified"));
  fireEvent.click(screen.getByRole("button", { name: t("vps.restore.review") }));
  fireEvent.click(await screen.findByRole("button", { name: t("vps.restore.action") }));
  await screen.findByText("the backup password is incorrect", { exact: false });
  expect((screen.getByLabelText(t("vps.common.backupPassword")) as HTMLInputElement).value).toBe("");
});
