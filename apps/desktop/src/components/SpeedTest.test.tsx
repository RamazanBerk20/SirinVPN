import { afterEach, expect, it, vi } from "vitest";
import { act, cleanup, fireEvent, render, screen } from "@testing-library/react";
import { api } from "../api";
import { t } from "../i18n";
import { SpeedTest, speedTestPhase } from "./SpeedTest";

vi.mock("../api", () => ({ api: { speedTest: vi.fn() } }));

afterEach(() => { cleanup(); vi.mocked(api.speedTest).mockReset(); });

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

it("shows the phase and time left while it runs, since it can't be cancelled", async () => {
  vi.useFakeTimers();
  vi.mocked(api.speedTest).mockReturnValue(new Promise(() => {}));
  render(<SpeedTest serverId="server" />);
  fireEvent.click(screen.getByRole("button", { name: t("maintenance.speedTest.run") }));
  expect(screen.queryByRole("button")).toBeNull();
  await act(async () => { await vi.advanceTimersByTimeAsync(4000); });
  expect(screen.getByText(t("settings.speedTest.left", { phase: t("settings.speedTest.phase.download"), seconds: "16" }))).toBeTruthy();
  expect([0, 1.9, 2, 9.9, 10, 17.9, 18, 40].map(speedTestPhase)).toEqual(["idle", "idle", "download", "download", "upload", "upload", "finishing", "finishing"]);
  vi.useRealTimers();
});
