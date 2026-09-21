import { act, cleanup, renderHook } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { emptyLocalStatus } from "./useDesktopStatus";
import { withTrafficRates } from "./trafficSample";
import { useTunnelDuration } from "./useTunnelDuration";
import type { LocalTunnelStatus } from "../types";

const connected: LocalTunnelStatus = {
  ...emptyLocalStatus,
  state: "connected",
  server_id: "a",
  counter_epoch: "first",
  tunnel_uptime_seconds: 10,
};
beforeEach(() =>
  vi.useFakeTimers({ toFake: ["setInterval", "clearInterval", "performance"] }),
);
afterEach(() => {
  cleanup();
  vi.useRealTimers();
  vi.restoreAllMocks();
});

describe("tunnel duration clock", () => {
  it("stops hidden timers and rejects an old observation on resume", () => {
    let hidden = false;
    vi.spyOn(document, "hidden", "get").mockImplementation(() => hidden);
    const { result, rerender } = renderHook(({ local }) => useTunnelDuration(local, "a"), {
      initialProps: { local: withTrafficRates(connected, 0, null) },
    });
    act(() => { hidden = true; document.dispatchEvent(new Event("visibilitychange")); });
    expect(vi.getTimerCount()).toBe(0);
    act(() => vi.advanceTimersByTime(20_000));
    act(() => { hidden = false; document.dispatchEvent(new Event("visibilitychange")); });
    expect(result.current).toBeUndefined();
    rerender({ local: withTrafficRates({ ...connected, tunnel_uptime_seconds: 30 }, performance.now(), null) });
    expect(result.current).toBe(30);
    expect(vi.getTimerCount()).toBe(1);
  });
  it("ticks every second between local readings and keeps its anchor through unrelated renders", () => {
    const sample = withTrafficRates(connected, performance.now(), null);
    const { result, rerender } = renderHook(
      ({ local }) => useTunnelDuration(local, "a"),
      { initialProps: { local: sample } },
    );
    expect(result.current).toBe(10);
    for (const seconds of [11, 12, 13]) {
      act(() => vi.advanceTimersByTime(1000));
      expect(result.current).toBe(seconds);
      rerender({ local: { ...sample } });
      expect(result.current).toBe(seconds);
    }
    act(() => vi.advanceTimersByTime(1000));
    rerender({
      local: withTrafficRates(
        { ...connected, tunnel_uptime_seconds: 14 },
        performance.now(),
        null,
      ),
    });
    expect(result.current).toBe(14);
    act(() => vi.advanceTimersByTime(1000));
    expect(result.current).toBe(15);
  });

  it("stops on disconnect or unknown state and starts from the next tunnel's measured duration", () => {
    const { result, rerender } = renderHook(
      ({ local }) => useTunnelDuration(local, "a"),
      { initialProps: { local: withTrafficRates(connected, 0, null) } },
    );
    act(() => vi.advanceTimersByTime(2000));
    expect(result.current).toBe(12);
    for (const state of ["unknown", "disconnected"] as const) {
      rerender({ local: { ...connected, state } });
      expect(result.current).toBeUndefined();
      expect(vi.getTimerCount()).toBe(0);
    }
    rerender({
      local: withTrafficRates(
        { ...connected, counter_epoch: "second", tunnel_uptime_seconds: 1 },
        performance.now(),
        null,
      ),
    });
    expect(result.current).toBe(1);
    act(() => vi.advanceTimersByTime(1000));
    expect(result.current).toBe(2);
    rerender({ local: { ...connected, server_id: "another" } });
    expect(result.current).toBeUndefined();
  });

  it("stops extrapolating stale readings and recovers from a fresh observation even if uptime is unchanged", () => {
    const { result, rerender } = renderHook(
      ({ local }) => useTunnelDuration(local, "a"),
      { initialProps: { local: withTrafficRates(connected, 0, null) } },
    );
    act(() => vi.advanceTimersByTime(16_000));
    expect(result.current).toBeUndefined();
    rerender({ local: withTrafficRates(connected, performance.now(), null) });
    expect(result.current).toBe(10);
    act(() => vi.advanceTimersByTime(1000));
    expect(result.current).toBe(11);
  });

  it("does not invent missing measurements or extrapolate without an observed session", () => {
    const { result, rerender } = renderHook(
      ({ local }) => useTunnelDuration(local, "a"),
      { initialProps: { local: connected } },
    );
    expect(result.current).toBe(10);
    expect(vi.getTimerCount()).toBe(0);
    for (const tunnel_uptime_seconds of [undefined, Number.NaN, -1]) {
      rerender({ local: { ...connected, tunnel_uptime_seconds } });
      expect(result.current).toBeUndefined();
    }
  });
});
