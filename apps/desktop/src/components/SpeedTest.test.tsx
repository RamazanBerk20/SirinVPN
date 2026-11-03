import { afterEach, expect, it, vi } from "vitest";
import { act, cleanup, fireEvent, render, screen } from "@testing-library/react";
import { api } from "../api";
import { t } from "../i18n";
import { SpeedTest, speedTestPhase } from "./SpeedTest";

vi.mock("../api", () => ({ api: { speedTest: vi.fn(), cancelSpeedTest: vi.fn() } }));

afterEach(() => { cleanup(); vi.mocked(api.speedTest).mockReset(); vi.mocked(api.cancelSpeedTest).mockReset(); });

it("runs only on request and labels the result as tunnel-to-VPS throughput", async () => {
  vi.mocked(api.speedTest).mockResolvedValue({
    download_bits_per_second: 94_230_000, upload_bits_per_second: 12_000_000,
    idle_latency_micros: 41_250, download_latency_micros: 180_000, upload_latency_micros: null,
  });
  render(<SpeedTest serverId="server" />);
  expect(api.speedTest).not.toHaveBeenCalled();
  expect(screen.getByText(t("maintenance.speedTest.description"))).toBeTruthy();
  fireEvent.click(screen.getByRole("button", { name: t("maintenance.speedTest.run") }));
  expect(await screen.findByText("94.2 Mbit/s")).toBeTruthy();
  expect(api.speedTest).toHaveBeenCalledWith("server");
  expect(screen.getByText("12 Mbit/s")).toBeTruthy();
  expect(screen.getByText("41.3 ms")).toBeTruthy();
  expect(screen.getByText(t("maintenance.speedTest.notMeasured"))).toBeTruthy();
  expect(screen.getByRole("button", { name: t("maintenance.speedTest.again") })).toBeTruthy();
});

it("shows the native explanation when the VPS refuses", async () => {
  vi.mocked(api.speedTest).mockRejectedValue(new Error("Only the Owner or an Admin can run the speed test."));
  render(<SpeedTest serverId="server" />);
  fireEvent.click(screen.getByRole("button", { name: t("maintenance.speedTest.run") }));
  expect((await screen.findByRole("alert")).textContent).toContain("Only the Owner or an Admin can run the speed test.");
});

it("shows the phase and time left while it runs", async () => {
  vi.useFakeTimers();
  vi.mocked(api.speedTest).mockReturnValue(new Promise(() => {}));
  render(<SpeedTest serverId="server" />);
  fireEvent.click(screen.getByRole("button", { name: t("maintenance.speedTest.run") }));
  expect(screen.queryByRole("button", { name: t("maintenance.speedTest.run") })).toBeNull();
  await act(async () => { await vi.advanceTimersByTimeAsync(4000); });
  expect(screen.getByText(t("settings.speedTest.left", { phase: t("settings.speedTest.phase.download"), seconds: "16" }))).toBeTruthy();
  expect([0, 1.9, 2, 9.9, 10, 17.9, 18, 40].map(speedTestPhase)).toEqual(["idle", "idle", "download", "download", "upload", "upload", "finishing", "finishing"]);
  vi.useRealTimers();
});

it("cancels on request and shows a neutral note with the Run button back", async () => {
  let finish!: (result: null) => void;
  vi.mocked(api.speedTest).mockReturnValue(new Promise((done) => { finish = done; }));
  vi.mocked(api.cancelSpeedTest).mockImplementation(async () => finish(null));
  vi.useFakeTimers({ shouldAdvanceTime: true });
  render(<SpeedTest serverId="server" />);
  fireEvent.click(screen.getByRole("button", { name: t("maintenance.speedTest.run") }));
  fireEvent.click(screen.getByRole("button", { name: t("settings.speedTest.cancel") }));
  // The VPS's one-minute limit counts from the cancelled start: say so instead of failing a rerun.
  expect(await screen.findByText(t("settings.speedTest.cancelledWait", { seconds: "60" }))).toBeTruthy();
  expect(api.cancelSpeedTest).toHaveBeenCalled();
  expect(screen.queryByRole("alert")).toBeNull();
  const again = screen.getByRole("button", { name: t("maintenance.speedTest.run") });
  expect(again.matches(":disabled")).toBe(true);
  expect(screen.queryByRole("button", { name: t("settings.speedTest.cancel") })).toBeNull();
  await act(async () => { await vi.advanceTimersByTimeAsync(61_000); });
  expect(screen.getByText(t("settings.speedTest.cancelled"))).toBeTruthy();
  expect(again.matches(":disabled")).toBe(false);
  vi.useRealTimers();
});

it("stops a running test when the dialog closes", () => {
  vi.mocked(api.speedTest).mockReturnValue(new Promise(() => {}));
  const view = render(<SpeedTest serverId="server" />);
  fireEvent.click(screen.getByRole("button", { name: t("maintenance.speedTest.run") }));
  expect(api.cancelSpeedTest).not.toHaveBeenCalled();
  view.unmount();
  expect(api.cancelSpeedTest).toHaveBeenCalledOnce();
});
