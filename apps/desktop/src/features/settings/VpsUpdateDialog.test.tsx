import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { api } from "../../api";
import type { ServerProfile } from "../../types";
import { VpsUpdateDialog } from "./VpsUpdateDialog";
import { t } from "../../i18n";
import type { VpsReleaseCandidate, VpsReleaseStatus } from "./vpsRelease";

vi.mock("../../api", () => ({ api: {
  getSshLogin: vi.fn(), saveSshLogin: vi.fn(), forgetSshLogin: vi.fn(), inspectSshHost: vi.fn(), trustSshHost: vi.fn(),
  manageVpsRelease: vi.fn(), prepareVpsBaseline: vi.fn(), installVpsBaseline: vi.fn(), discardVpsBaseline: vi.fn(), repairServer: vi.fn(),
} }));
const fingerprint = `SHA256:${"A".repeat(43)}`;
const source = "https://releases.example/stable/";
const profile = { id: "a", name: "My VPS", endpoint: { host: "vps.example" }, role: "owner" } as ServerProfile;
const status: VpsReleaseStatus = {
  release: { installed: { active_release_version: "1.0.1", active_release_sequence: "1", highest_accepted_release_sequence: "1",
    channel: "stable", active_artifact: { sha256: "1".repeat(64), target: "x86_64-unknown-linux-gnu" } },
    rollback_version: null, recovery_pending: false },
  security_updates: { schema_version: 1, enabled: false, source, channel: "stable" }, automatic_outcome: null, installed_binary_matches: true,
};
const candidate: VpsReleaseCandidate = { release_version: "1.0.2", release_sequence: "2", security_update: true, channel: "stable",
  manifest_sha256: "2".repeat(64), artifact_sha256: "3".repeat(64), artifact_target: "x86_64-unknown-linux-gnu",
  artifact_size_bytes: 1024, action: "upgrade", can_install: true, baseline_required: false };

beforeEach(() => {
  vi.resetAllMocks();
  const values = new Map<string, string>();
  vi.stubGlobal("localStorage", {
    getItem: (key: string) => values.get(key) ?? null,
    setItem: (key: string, value: string) => { values.set(key, value); },
    removeItem: (key: string) => { values.delete(key); },
  });
  vi.mocked(api.getSshLogin).mockResolvedValue(null);
  vi.mocked(api.saveSshLogin).mockResolvedValue({ username: "root", ssh_port: 22, authentication: "agent", private_key_path: null });
  vi.mocked(api.inspectSshHost).mockResolvedValue({ fingerprint, status: "trusted" });
  vi.mocked(api.trustSshHost).mockResolvedValue(undefined);
  vi.mocked(api.discardVpsBaseline).mockResolvedValue(undefined);
  let current = structuredClone(status);
  vi.mocked(api.manageVpsRelease).mockImplementation(async ({ operation }) => {
    if (operation.action === "check") return candidate;
    if (operation.action === "install") current = { ...current, release: { ...current.release, installed: { ...current.release.installed!, active_release_version: candidate.release_version } } };
    if (operation.action === "configure") current = { ...current, security_updates: { ...current.security_updates, enabled: operation.enabled, source: operation.source } };
    return current;
  });
});
afterEach(() => { cleanup(); vi.unstubAllGlobals(); });
const toggle = () => screen.getByRole("switch", { name: new RegExp(t("vps.update.schedule.toggle")) }) as HTMLInputElement;
async function setup(onRepair?: () => void) {
  const completed = vi.fn().mockResolvedValue(undefined);
  render(<VpsUpdateDialog profile={profile} open onOpenChange={vi.fn()} disconnected onCompleted={completed} onRepair={onRepair} />);
  const agent = await screen.findByRole("button", { name: t("ssh.auth.agent") });
  await waitFor(() => expect(agent.matches(":disabled")).toBe(false));
  fireEvent.click(agent);
  fireEvent.click(screen.getByRole("button", { name: t("common.action.continue") }));
  await screen.findByText("1.0.1");
  return completed;
}

it("checks without installing or enabling a schedule and binds installation to the reviewed manifest", async () => {
  const completed = await setup();
  expect(toggle().checked).toBe(false);
  fireEvent.click(screen.getByRole("button", { name: t("vps.update.action.check") }));
  const install = await screen.findByRole("button", { name: t("vps.update.action.install", { version: "1.0.2" }) });
  expect(api.manageVpsRelease).not.toHaveBeenCalledWith(expect.objectContaining({ operation: expect.objectContaining({ action: "install" }) }));
  expect(api.manageVpsRelease).not.toHaveBeenCalledWith(expect.objectContaining({ operation: expect.objectContaining({ action: "configure" }) }));
  fireEvent.click(install);
  await screen.findByText(t("vps.update.done.installed", { version: "1.0.2" }));
  expect(api.manageVpsRelease).toHaveBeenCalledWith(expect.objectContaining({ server_id: "a",
    ssh: expect.objectContaining({ host: "vps.example", host_key_sha256: fingerprint }),
    operation: { action: "install", manifest_sha256: candidate.manifest_sha256 } }));
  expect(api.repairServer).not.toHaveBeenCalled();
  await waitFor(() => expect(completed).toHaveBeenCalledOnce());
});

it("shows a signed summary under the release heading and nothing for a release without one", async () => {
  const notes = "Restarts services faster after an update.";
  const original = vi.mocked(api.manageVpsRelease).getMockImplementation()!;
  const review = async () => {
    fireEvent.click(screen.getByRole("button", { name: t("vps.update.action.check") }));
    return screen.findByRole("heading", { name: t("vps.update.review.title", { version: "1.0.2" }) });
  };
  vi.mocked(api.manageVpsRelease).mockImplementation(async (input) =>
    input.operation.action === "check" ? { ...candidate, release_notes: notes } : original(input));
  await setup();
  expect((await review()).nextElementSibling?.textContent).toBe(`${t("release.candidate.whatsNew")} ${notes}`);
  cleanup();
  vi.mocked(api.manageVpsRelease).mockImplementation(original);
  await setup();
  await review();
  expect(screen.queryByText(t("release.candidate.whatsNew"))).toBeNull();
});

it("clears a reviewed candidate when the release source changes and rejects private URL parameters", async () => {
  await setup(); fireEvent.click(screen.getByRole("button", { name: t("vps.update.action.check") }));
  await screen.findByRole("button", { name: t("vps.update.action.install", { version: "1.0.2" }) });
  fireEvent.click(screen.getByRole("button", { name: t("vps.update.source.change") }));
  fireEvent.change(screen.getByLabelText(new RegExp(`^${t("vps.update.source.label")}`)), { target: { value: "https://releases.example/?device=private" } });
  expect(screen.queryByRole("button", { name: t("vps.update.action.install", { version: "1.0.2" }) })).toBeNull();
  expect((screen.getByRole("button", { name: t("vps.update.action.check") }) as HTMLButtonElement).disabled).toBe(true);
});

it("saves automatic security updates only when the switch changes", async () => {
  await setup();
  expect(api.manageVpsRelease).not.toHaveBeenCalledWith(expect.objectContaining({ operation: expect.objectContaining({ action: "configure" }) }));
  fireEvent.click(toggle());
  await screen.findByText(t("vps.update.schedule.enabled"));
  expect(toggle().checked).toBe(true);
  expect(api.manageVpsRelease).toHaveBeenCalledWith(expect.objectContaining({ operation: { action: "configure", enabled: true, source } }));
});

it("reports a rejected candidate without claiming that installation completed", async () => {
  const completed = await setup(); fireEvent.click(screen.getByRole("button", { name: t("vps.update.action.check") }));
  const button = await screen.findByRole("button", { name: t("vps.update.action.install", { version: "1.0.2" }) });
  vi.mocked(api.manageVpsRelease).mockRejectedValueOnce(new Error("The release signing key is revoked."));
  fireEvent.click(button);
  await screen.findByText("The release signing key is revoked.", { exact: false });
  expect(screen.queryByText(t("vps.update.done.installed", { version: "1.0.2" }))).toBeNull();
  expect(completed).not.toHaveBeenCalled();
});

it("prepares a first baseline for a legacy VPS and waits for its separate install action", async () => {
  vi.mocked(api.manageVpsRelease).mockRejectedValueOnce(new Error("Repair the VPS components once to install the signed release coordinator."));
  vi.mocked(api.prepareVpsBaseline).mockResolvedValue({ release_version: "1.0.2", release_sequence: "2", channel: "stable", security_update: true,
    manifest_sha256: candidate.manifest_sha256, artifact: { sha256: candidate.artifact_sha256, target: candidate.artifact_target, size_bytes: 1024 } });
  vi.mocked(api.installVpsBaseline).mockImplementation(async () => {
    vi.mocked(api.manageVpsRelease).mockResolvedValue({ ...status, release: { ...status.release, installed: { ...status.release.installed!, active_release_version: candidate.release_version } } });
    return {};
  });
  render(<VpsUpdateDialog profile={profile} open onOpenChange={vi.fn()} disconnected onCompleted={vi.fn().mockResolvedValue(undefined)} />);
  const agent = await screen.findByRole("button", { name: t("ssh.auth.agent") });
  await waitFor(() => expect(agent.matches(":disabled")).toBe(false));
  fireEvent.click(agent);
  fireEvent.click(screen.getByRole("button", { name: t("common.action.continue") }));
  await screen.findByText(t("vps.update.description.setup"));
  fireEvent.change(screen.getByLabelText(new RegExp(`^${t("vps.update.source.label")}`)), { target: { value: source } });
  fireEvent.click(screen.getByRole("button", { name: t("vps.update.action.verify") }));
  const install = await screen.findByRole("button", { name: t("vps.update.action.installAndFinish") });
  expect(api.installVpsBaseline).not.toHaveBeenCalled();
  fireEvent.click(install);
  await screen.findByText(t("vps.update.done.setUp", { version: "1.0.2" }));
  expect(api.installVpsBaseline).toHaveBeenCalledWith(expect.objectContaining({ manifest_sha256: candidate.manifest_sha256 }));
  expect(api.repairServer).not.toHaveBeenCalled();
});

it("discards a closed review and ignores a release check that completes after reopening", async () => {
  let finish!: (value: VpsReleaseCandidate) => void;
  vi.mocked(api.manageVpsRelease).mockImplementation(async ({ operation }) => operation.action === "check"
    ? new Promise<VpsReleaseCandidate>((resolve) => { finish = resolve; }) : status);
  const props = { profile, onOpenChange: vi.fn(), disconnected: true, onCompleted: vi.fn().mockResolvedValue(undefined) };
  const view = render(<VpsUpdateDialog {...props} open />);
  const agent = await screen.findByRole("button", { name: t("ssh.auth.agent") });
  await waitFor(() => expect(agent.matches(":disabled")).toBe(false));
  fireEvent.click(agent);
  fireEvent.click(screen.getByRole("button", { name: t("common.action.continue") }));
  fireEvent.click(await screen.findByRole("button", { name: t("vps.update.action.check") }));
  await waitFor(() => expect(finish).toBeDefined());
  view.rerender(<VpsUpdateDialog {...props} open={false} />);
  view.rerender(<VpsUpdateDialog {...props} open />);
  await act(async () => { finish(candidate); });
  expect(screen.queryByRole("button", { name: t("vps.update.action.install", { version: "1.0.2" }) })).toBeNull();
  expect(screen.getByRole("button", { name: t("common.action.continue") })).toBeTruthy();
  expect(api.discardVpsBaseline).toHaveBeenCalledWith(profile.id);
});

it("keeps disabling an existing schedule possible after a source check fails", async () => {
  let current = { ...status, security_updates: { ...status.security_updates, enabled: true } };
  vi.mocked(api.manageVpsRelease).mockImplementation(async ({ operation }) => {
    if (operation.action === "check") throw new Error("Release signature verification failed.");
    if (operation.action === "configure") current = { ...current, security_updates: { ...current.security_updates, enabled: operation.enabled } };
    return current;
  });
  await setup();
  fireEvent.click(screen.getByRole("button", { name: t("vps.update.action.check") }));
  await screen.findByText("Release signature verification failed.", { exact: false });
  fireEvent.click(screen.getByRole("button", { name: t("vps.update.source.change") }));
  fireEvent.change(screen.getByLabelText(new RegExp(`^${t("vps.update.source.label")}`)), { target: { value: "invalid source" } });
  expect(toggle().matches(":disabled")).toBe(false);
  fireEvent.click(toggle());
  await screen.findByText(t("vps.update.schedule.disabled"));
  expect(api.manageVpsRelease).toHaveBeenCalledWith(expect.objectContaining({ operation: { action: "configure", enabled: false, source: null } }));
});

it("puts the switch back when the VPS rejects or doesn't confirm the schedule", async () => {
  await setup();
  vi.mocked(api.manageVpsRelease).mockRejectedValueOnce(new Error("Schedule write failed."));
  fireEvent.click(toggle());
  await screen.findByText("Schedule write failed.", { exact: false });
  expect(toggle().checked).toBe(false);
  expect(screen.queryByText(t("vps.update.schedule.enabled"))).toBeNull();
  vi.mocked(api.manageVpsRelease).mockResolvedValue(status);
  fireEvent.click(toggle());
  await screen.findByText(t("vps.update.error.scheduleNotConfirmed"), { exact: false });
  expect(toggle().checked).toBe(false);
});

it("offers Repair for a receipt mismatch and blocks checking until repaired", async () => {
  vi.mocked(api.manageVpsRelease).mockResolvedValue({ ...status, installed_binary_matches: false });
  const repair = vi.fn();
  await setup(repair);
  expect(screen.getByRole("button", { name: t("vps.update.action.check") }).matches(":disabled")).toBe(true);
  expect(screen.getByText(t("vps.update.blocked.mismatch"))).toBeTruthy();
  fireEvent.click(screen.getByRole("button", { name: t("vps.update.action.repair") }));
  expect(repair).toHaveBeenCalledOnce();
});

it("rolls back only after a confirmation that names the version", async () => {
  vi.mocked(api.manageVpsRelease).mockResolvedValue({ ...status, release: { ...status.release, rollback_version: "1.0.0" } });
  const confirm = vi.fn().mockReturnValueOnce(false).mockReturnValueOnce(true);
  vi.stubGlobal("confirm", confirm);
  await setup();
  const rollback = screen.getByRole("button", { name: t("vps.update.rollback.action", { version: "1.0.0" }) });
  fireEvent.click(rollback);
  await waitFor(() => expect(confirm).toHaveBeenCalledOnce());
  expect(confirm.mock.calls[0][0]).toContain(t("vps.update.rollback.confirmTitle", { version: "1.0.0" }));
  expect(api.manageVpsRelease).not.toHaveBeenCalledWith(expect.objectContaining({ operation: expect.objectContaining({ action: "rollback" }) }));
  fireEvent.click(rollback);
  await screen.findByText(t("vps.update.done.rolledBack", { version: "1.0.0" }));
  expect(api.manageVpsRelease).toHaveBeenCalledWith(expect.objectContaining({ operation: { action: "rollback", confirmed: true } }));
});

it("names an invalid release source at the field and says why checking is unavailable", async () => {
  await setup();
  fireEvent.click(screen.getByRole("button", { name: t("vps.update.source.change") }));
  fireEvent.change(screen.getByLabelText(new RegExp(`^${t("vps.update.source.label")}`)), { target: { value: "http://releases.example/" } });
  expect(screen.getByText(t("vps.update.source.invalid"))).toBeTruthy();
  expect(screen.getByLabelText(new RegExp(`^${t("vps.update.source.label")}`)).getAttribute("aria-invalid")).toBe("true");
  expect(screen.getByText(t("vps.update.blocked.source"))).toBeTruthy();
});

it("finishes setup using a matching verified installation without reinstalling it", async () => {
  let installed = false;
  vi.mocked(api.manageVpsRelease).mockImplementation(async ({ operation }) => {
    if (operation.action === "check") return { ...candidate, baseline_required: true, action: "initialize" };
    if (operation.action === "install") installed = true;
    return { ...status, release: { ...status.release, installed: installed ? { ...status.release.installed!, active_release_version: candidate.release_version } : null } };
  });
  render(<VpsUpdateDialog profile={profile} open onOpenChange={vi.fn()} disconnected onCompleted={vi.fn().mockResolvedValue(undefined)} />);
  const agent = await screen.findByRole("button", { name: t("ssh.auth.agent") });
  await waitFor(() => expect(agent.matches(":disabled")).toBe(false));
  fireEvent.click(agent);
  fireEvent.click(screen.getByRole("button", { name: t("common.action.continue") }));
  fireEvent.click(await screen.findByRole("button", { name: t("vps.update.action.verify") }));
  const finish = await screen.findByRole("button", { name: t("vps.update.action.finishSetup") });
  expect(api.prepareVpsBaseline).not.toHaveBeenCalled();
  expect(api.installVpsBaseline).not.toHaveBeenCalled();
  fireEvent.click(finish);
  await screen.findByText(t("vps.update.done.setUp", { version: "1.0.2" }));
  expect(api.manageVpsRelease).toHaveBeenCalledWith(expect.objectContaining({ operation: { action: "install", manifest_sha256: candidate.manifest_sha256 } }));
});

it("blocks Escape and closing during installation and leaves a failed operation reviewable", async () => {
  let reject!: (reason: Error) => void;
  const changeOpen = vi.fn();
  render(<VpsUpdateDialog profile={profile} open onOpenChange={changeOpen} disconnected onCompleted={vi.fn().mockResolvedValue(undefined)} />);
  const agent = await screen.findByRole("button", { name: t("ssh.auth.agent") });
  await waitFor(() => expect(agent.matches(":disabled")).toBe(false));
  fireEvent.click(agent); fireEvent.click(screen.getByRole("button", { name: t("common.action.continue") }));
  fireEvent.click(await screen.findByRole("button", { name: t("vps.update.action.check") }));
  const install = await screen.findByRole("button", { name: t("vps.update.action.install", { version: "1.0.2" }) });
  vi.mocked(api.manageVpsRelease).mockImplementationOnce(() => new Promise((_, fail) => { reject = fail; }));
  fireEvent.click(install);
  await waitFor(() => expect(reject).toBeDefined());
  expect(screen.getAllByRole("button", { name: t("common.action.close") }).every((button) => button.matches(":disabled"))).toBe(true);
  fireEvent.keyDown(screen.getByRole("dialog"), { key: "Escape", code: "Escape" });
  expect(changeOpen).not.toHaveBeenCalled();
  await act(async () => reject(new Error("The update was interrupted; recover its transaction before retrying.")));
  await screen.findByText("The update was interrupted; recover its transaction before retrying.", { exact: false });
  expect(screen.getAllByRole("button", { name: t("common.action.close") }).every((button) => !button.matches(":disabled"))).toBe(true);
});

it("remembers only a verified source for this VPS and never carries it to another server", async () => {
  await setup();
  fireEvent.click(screen.getByRole("button", { name: t("vps.update.action.check") }));
  await screen.findByRole("button", { name: t("vps.update.action.install", { version: "1.0.2" }) });
  cleanup();
  vi.mocked(api.manageVpsRelease).mockResolvedValue({ ...status, security_updates: { ...status.security_updates, source: null } });
  await setup();
  expect(screen.getByText(source)).toBeTruthy();
  expect(screen.queryByRole("textbox", { name: new RegExp(`^${t("vps.update.source.label")}`) })).toBeNull();
  cleanup();
  render(<VpsUpdateDialog profile={{ ...profile, id: "b" }} open onOpenChange={vi.fn()} disconnected onCompleted={vi.fn().mockResolvedValue(undefined)} />);
  const agent = await screen.findByRole("button", { name: t("ssh.auth.agent") });
  await waitFor(() => expect(agent.matches(":disabled")).toBe(false));
  fireEvent.click(agent); fireEvent.click(screen.getByRole("button", { name: t("common.action.continue") }));
  const input = await screen.findByRole("textbox", { name: new RegExp(`^${t("vps.update.source.label")}`) });
  expect((input as HTMLInputElement).value).toBe("");
});

it("does not claim installation when the VPS cannot confirm the reviewed version", async () => {
  const completed = await setup();
  fireEvent.click(screen.getByRole("button", { name: t("vps.update.action.check") }));
  const install = await screen.findByRole("button", { name: t("vps.update.action.install", { version: "1.0.2" }) });
  vi.mocked(api.manageVpsRelease).mockResolvedValue(status);
  fireEvent.click(install);
  await screen.findByText(t("vps.update.error.notConfirmed"), { exact: false });
  expect(screen.queryByText(t("vps.update.done.installed", { version: "1.0.2" }))).toBeNull();
  expect(completed).not.toHaveBeenCalled();
});
