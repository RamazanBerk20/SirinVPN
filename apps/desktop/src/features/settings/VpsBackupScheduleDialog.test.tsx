import { act, cleanup, fireEvent, render, renderHook, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { api } from "../../api";
import { t } from "../../i18n";
import { open } from "../../lib/nativeDialog";
import type { ServerProfile, VpsBackupSchedule } from "../../types";
import { VpsBackupScheduleDialog } from "./VpsBackupScheduleDialog";
import {
  scheduleSummary,
  updateVpsBackupSchedule,
  useScheduledVpsBackups,
} from "./vpsBackupSchedules";

vi.mock("../../api", () => ({
  api: {
    getSshLogin: vi.fn(),
    vpsBackupSchedules: vi.fn(),
    setVpsBackupSchedule: vi.fn(),
    disableVpsBackupSchedule: vi.fn(),
    runScheduledVpsBackup: vi.fn(),
  },
}));
vi.mock("../../lib/nativeDialog", () => ({ open: vi.fn() }));

const now = Math.floor(Date.now() / 1000);
const profile = { id: "a", name: "My VPS", endpoint: { host: "vps.example" }, role: "owner" } as ServerProfile;
const schedule = (overrides: Partial<VpsBackupSchedule> = {}): VpsBackupSchedule => ({
  server_id: "a",
  folder: "/backups",
  keep: 4,
  interval_days: 7,
  enabled_at: now - 30 * 86_400,
  last_success: now - 3 * 86_400,
  last_failure: null,
  due: false,
  stale: false,
  ...overrides,
});

beforeEach(() => {
  vi.resetAllMocks();
  vi.mocked(api.getSshLogin).mockResolvedValue({ username: "root", ssh_port: 22, authentication: "agent", private_key_path: null });
  vi.mocked(api.vpsBackupSchedules).mockResolvedValue([]);
  updateVpsBackupSchedule("a", null);
  updateVpsBackupSchedule("b", null);
});
afterEach(() => {
  cleanup();
  vi.useRealTimers();
});

it("runs only due schedules, only while disconnected, and keeps the reported failure", async () => {
  vi.useFakeTimers();
  const failed = schedule({ server_id: "b", due: false, last_failure: { at: now, message: "SSH timed out." } });
  vi.mocked(api.vpsBackupSchedules).mockResolvedValue([schedule({ due: false }), schedule({ server_id: "b", due: true })]);
  vi.mocked(api.runScheduledVpsBackup).mockResolvedValue(failed);

  const { rerender, unmount } = renderHook(({ ready }) => useScheduledVpsBackups(ready), { initialProps: { ready: false } });
  await act(async () => { await vi.advanceTimersByTimeAsync(20 * 60_000); });
  expect(api.runScheduledVpsBackup).not.toHaveBeenCalled();

  rerender({ ready: true });
  // A minute's grace after disconnecting before the first run.
  await act(async () => { await vi.advanceTimersByTimeAsync(59_000); });
  expect(api.runScheduledVpsBackup).not.toHaveBeenCalled();
  await act(async () => { await vi.advanceTimersByTimeAsync(1_000); });
  expect(api.runScheduledVpsBackup).toHaveBeenCalledExactlyOnceWith("b", false);
  unmount();

  render(<VpsBackupScheduleDialog profile={{ ...profile, id: "b" }} open onOpenChange={vi.fn()} disconnected />);
  expect(screen.getByText(t("vps.schedule.failed", { message: "SSH timed out." }))).toBeTruthy();
  expect(scheduleSummary(failed)).toBe(t("vps.schedule.summary.failed"));
});

it("turns a schedule on with a confirmed password and keeps it when editing", async () => {
  vi.mocked(open).mockResolvedValue("/media/backups");
  vi.mocked(api.setVpsBackupSchedule).mockImplementation(async (input) =>
    schedule({ folder: input.folder, keep: input.keep, interval_days: input.interval_days, last_success: null }),
  );
  render(<VpsBackupScheduleDialog profile={profile} open onOpenChange={vi.fn()} disconnected={false} />);
  const save = screen.getByRole("button", { name: t("vps.schedule.save") });
  fireEvent.click(screen.getByRole("button", { name: t("vps.schedule.chooseFolder") }));
  await waitFor(() => expect(screen.getByDisplayValue("/media/backups")).toBeTruthy());
  expect(save.matches(":disabled")).toBe(true);
  const [password, repeat] = screen.getAllByLabelText(/password/i);
  fireEvent.change(password, { target: { value: "correct horse battery" } });
  fireEvent.change(repeat, { target: { value: "correct horse battery" } });
  fireEvent.change(screen.getByRole("spinbutton"), { target: { value: "6" } });
  fireEvent.click(save);
  await waitFor(() => expect(api.setVpsBackupSchedule).toHaveBeenCalledExactlyOnceWith({
    server_id: "a", folder: "/media/backups", keep: 6, interval_days: 7, backup_password: "correct horse battery",
  }));
  expect(await screen.findByText(t("vps.schedule.noBackup"))).toBeTruthy();
  // Back up now waits for a disconnected device; editing keeps the saved password.
  expect(screen.getByRole("button", { name: t("vps.schedule.runNow") }).matches(":disabled")).toBe(true);
  fireEvent.change(screen.getByRole("combobox"), { target: { value: "1" } });
  fireEvent.click(save);
  await waitFor(() => expect(api.setVpsBackupSchedule).toHaveBeenLastCalledWith({
    server_id: "a", folder: "/media/backups", keep: 6, interval_days: 1,
  }));
});

it("explains a missing saved SSH login and turns the schedule off", async () => {
  vi.mocked(api.getSshLogin).mockResolvedValue(null);
  vi.mocked(api.disableVpsBackupSchedule).mockResolvedValue(undefined);
  vi.mocked(api.vpsBackupSchedules).mockResolvedValue([schedule({ stale: true, last_success: now - 10 * 86_400 })]);
  render(<VpsBackupScheduleDialog profile={profile} open onOpenChange={vi.fn()} disconnected />);
  expect(await screen.findByText(t("vps.schedule.loginMissing"))).toBeTruthy();
  expect(await screen.findByText(t("vps.schedule.stale"))).toBeTruthy();
  expect(screen.getByText(t("vps.schedule.lastBackup", { age: t("vps.schedule.age.days", { count: 10 }) }))).toBeTruthy();
  fireEvent.click(screen.getByRole("button", { name: t("vps.schedule.turnOff") }));
  await waitFor(() => expect(api.disableVpsBackupSchedule).toHaveBeenCalledExactlyOnceWith("a"));
  expect(screen.queryByRole("button", { name: t("vps.schedule.turnOff") })).toBeNull();
});
