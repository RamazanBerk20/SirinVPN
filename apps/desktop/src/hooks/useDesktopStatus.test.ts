import { act, cleanup, renderHook, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { emptyLocalStatus, useDesktopStatus } from "./useDesktopStatus";
import type { LocalStatusEvent, ServerProfile, ServerStatus, ServerStatusEvent } from "../types";

const mocked = vi.hoisted(() => ({
  localStatus: vi.fn(),
  serverStatus: vi.fn(),
  watchServerStatus: vi.fn(),
  watchLocalStatus: undefined as undefined | ((receive: (event: LocalStatusEvent) => void) => () => void),
}));
vi.mock("../api", () => ({ api: mocked }));
const subscriptions: {
  id: string;
  send: (event: ServerStatusEvent) => void;
  stop: ReturnType<typeof vi.fn>;
}[] = [];
beforeEach(() => {
  mocked.watchLocalStatus = undefined;
  subscriptions.length = 0;
  mocked.localStatus.mockResolvedValue({
    ...emptyLocalStatus,
    state: "connected",
    server_id: "first",
  });
  mocked.watchServerStatus.mockImplementation((id, send) => {
    const stop = vi.fn();
    subscriptions.push({ id, send, stop });
    return stop;
  });
});
afterEach(() => {
  cleanup();
  vi.resetAllMocks();
  vi.useRealTimers();
  vi.restoreAllMocks();
});
const remote = {
  server_name: "First server",
  caller_role: "owner",
  uptime_seconds: 10,
} as ServerStatus;
const reading = (
  status = remote,
  mode: "live" | "polling" = "live",
): ServerStatusEvent => ({
  kind: "status",
  status,
  mode,
  management_latency_ms: null,
});
async function setup() {
  const setServers = vi.fn();
  const hook = renderHook(() => useDesktopStatus("desktop", setServers));
  await waitFor(() => expect(subscriptions).toHaveLength(1));
  return { ...hook, setServers };
}

describe("desktop status stream", () => {
  it("publishes traffic observations without replacing connection control state", async () => {
    const { result } = await setup();
    const controls = result.current.localStatus;
    const sample = vi.fn();
    const stop = result.current.trafficUpdates.subscribe(sample);
    await act(() => result.current.refreshStatus({ ...controls, rx_bytes: 2048, tunnel_uptime_seconds: 30 }));
    expect(result.current.localStatus).toBe(controls);
    expect(sample).toHaveBeenCalledOnce();
    expect(result.current.trafficUpdates.getSnapshot()).toMatchObject({ rx_bytes: 2048, tunnel_uptime_seconds: 30 });
    await act(() => result.current.refreshStatus({ ...controls, kill_switch_enabled: true }));
    expect(result.current.localStatus.kill_switch_enabled).toBe(true);
    stop();
  });

  it("keeps Android rates between counter samples and uses their native timing", async () => {
    const { result } = await setup();
    const clock = vi.spyOn(performance, "now");
    const first = {
      ...emptyLocalStatus, state: "connected" as const, server_id: "first",
      counter_epoch: "session", byte_counters_available: true, tunnel_uptime_seconds: 10,
      counter_sampled_at_ms: 10_000, rx_bytes: 1000, tx_bytes: 500,
    };
    const send = async (status: typeof first, at: number) => {
      clock.mockReturnValue(at);
      await act(() => result.current.refreshStatus(status));
      return result.current.trafficUpdates.getSnapshot()!;
    };
    expect((await send(first, 100)).rx_bytes_per_second).toBeUndefined();
    const controls = result.current.localStatus;
    const second = { ...first, counter_sampled_at_ms: 12_000, tunnel_uptime_seconds: 12, rx_bytes: 5000, tx_bytes: 1500 };
    for (const at of [2100, 2110, 2500, 3500]) {
      expect(await send(second, at)).toMatchObject({ rx_bytes_per_second: 2000, tx_bytes_per_second: 500 });
    }
    expect(result.current.localStatus).toBe(controls);
    // A fresh native reading may arrive immediately after an unrelated status update.
    const third = { ...second, counter_sampled_at_ms: 14_000, tunnel_uptime_seconds: 14, rx_bytes: 13_000, tx_bytes: 3500 };
    expect(await send(third, 3520)).toMatchObject({ rx_bytes_per_second: 4000, tx_bytes_per_second: 1000 });
    expect(await send({ ...third, counter_sampled_at_ms: 16_000, tunnel_uptime_seconds: 16 }, 5500))
      .toMatchObject({ rx_bytes_per_second: 0, tx_bytes_per_second: 0 });
    expect((await send({ ...first, counter_epoch: "reconnected", counter_sampled_at_ms: 18_000 }, 7500)).rx_bytes_per_second).toBeUndefined();
  });

  it("pauses hidden streams and waits for fresh local identity before resuming", async () => {
    let hidden = false;
    vi.spyOn(document, "hidden", "get").mockImplementation(() => hidden);
    const locals: { send: (event: LocalStatusEvent) => void; stop: ReturnType<typeof vi.fn> }[] = [];
    mocked.watchLocalStatus = (send) => {
      const stop = vi.fn(); locals.push({ send, stop }); return stop;
    };
    const setServers = vi.fn();
    const { result, unmount } = renderHook(() => useDesktopStatus("desktop", setServers));
    const sendLocal = (index: number, id: string) => act(() => locals[index].send({
      status: { ...emptyLocalStatus, state: "connected", server_id: id },
      sequence: 1, generation: 1, phase: "connected", stale: false,
    }));
    sendLocal(0, "first");
    act(() => subscriptions[0].send(reading()));
    act(() => { hidden = true; document.dispatchEvent(new Event("visibilitychange")); });
    expect(locals[0].stop).toHaveBeenCalledOnce();
    expect(subscriptions[0].stop).toHaveBeenCalledOnce();
    setServers.mockClear();
    act(() => subscriptions[0].send(reading()));
    expect(result.current.serverStatus).toBeNull();
    expect(setServers).not.toHaveBeenCalled();
    act(() => { hidden = false; document.dispatchEvent(new Event("visibilitychange")); window.dispatchEvent(new Event("focus")); });
    expect(locals).toHaveLength(2);
    expect(subscriptions).toHaveLength(1);
    sendLocal(1, "second");
    expect(subscriptions).toHaveLength(2);
    expect(subscriptions[1].id).toBe("second");
    unmount();
    expect(locals[1].stop).toHaveBeenCalledOnce();
    expect(subscriptions[1].stop).toHaveBeenCalledOnce();
  });

  it("also pauses the legacy local polling fallback while hidden", async () => {
    vi.useFakeTimers();
    let hidden = false;
    vi.spyOn(document, "hidden", "get").mockImplementation(() => hidden);
    const setServers = vi.fn();
    await act(async () => { renderHook(() => useDesktopStatus("desktop", setServers)); });
    const calls = mocked.localStatus.mock.calls.length;
    await act(async () => { hidden = true; document.dispatchEvent(new Event("visibilitychange")); await vi.advanceTimersByTimeAsync(60_000); });
    expect(mocked.localStatus).toHaveBeenCalledTimes(calls);
    await act(async () => { hidden = false; document.dispatchEvent(new Event("visibilitychange")); });
    expect(mocked.localStatus).toHaveBeenCalledTimes(calls + 1);
  });
  it("applies pushed readings without another status request or refresh flicker", async () => {
    const { result, setServers } = await setup();
    act(() => subscriptions[0].send(reading()));
    expect(result.current.serverStatus?.uptime_seconds).toBe(10);
    act(() =>
      subscriptions[0].send(reading({ ...remote, uptime_seconds: 11 })),
    );
    expect(result.current.serverStatus?.uptime_seconds).toBe(11);
    await act(() => result.current.refreshStatus());
    expect(result.current.freshness).toMatchObject({
      management: "ready",
      mode: "live",
    });
    expect(subscriptions).toHaveLength(1);
    expect(mocked.serverStatus).not.toHaveBeenCalled();
    const profiles = [
      { id: "first", role: "owner", administrator: false },
    ] as ServerProfile[];
    expect(setServers.mock.calls.at(-1)![0](profiles)).toBe(profiles);
  });

  it("cancels on disconnect and rejects late readings and authority", async () => {
    const { result, setServers } = await setup();
    mocked.localStatus.mockResolvedValue(emptyLocalStatus);
    await act(() => result.current.refreshStatus());
    act(() => subscriptions[0].send(reading()));
    expect(subscriptions[0].stop).toHaveBeenCalledOnce();
    expect(result.current.localStatus.state).toBe("disconnected");
    expect(result.current.serverStatus).toBeNull();
    expect(setServers).not.toHaveBeenCalled();
  });

  it("clears the previous server and ignores its messages after switching", async () => {
    const { result } = await setup();
    act(() => subscriptions[0].send(reading()));
    mocked.localStatus.mockResolvedValue({
      ...emptyLocalStatus,
      state: "connected",
      server_id: "second",
    });
    await act(() => result.current.refreshStatus());
    expect(subscriptions[0].stop).toHaveBeenCalledOnce();
    expect(subscriptions[1].id).toBe("second");
    expect(result.current.serverStatus).toBeNull();
    act(() => subscriptions[0].send(reading()));
    expect(result.current.serverStatus).toBeNull();
    act(() =>
      subscriptions[1].send(
        reading({ ...remote, server_name: "Second server" }),
      ),
    );
    expect(result.current.serverStatus?.server_name).toBe("Second server");
  });

  it("reconnects without changing the local tunnel and distinguishes legacy polling", async () => {
    const { result } = await setup();
    act(() => subscriptions[0].send(reading()));
    act(() => subscriptions[0].send({ kind: "state", state: "reconnecting" }));
    expect(result.current.localStatus.state).toBe("connected");
    expect(result.current.serverStatus).toBeNull();
    expect(result.current.freshness).toMatchObject({
      management: "reconnecting",
      updatedAt: null,
    });
    act(() => subscriptions[0].send(reading(remote, "polling")));
    expect(result.current.freshness.mode).toBe("polling");
    act(() => subscriptions[0].send(reading()));
    expect(result.current.freshness.mode).toBe("live");
  });

  it("stops the stream on local failure, preserves protection, and resumes automatically", async () => {
    const { result } = await setup();
    mocked.localStatus.mockResolvedValue({
      ...emptyLocalStatus,
      state: "connected",
      server_id: "first",
      kill_switch_enabled: true,
    });
    await act(() => result.current.refreshStatus());
    mocked.localStatus.mockRejectedValue(new Error("helper unavailable"));
    await act(() => result.current.refreshStatus());
    act(() => subscriptions[0].send(reading()));
    expect(result.current.localStatus).toMatchObject({
      state: "unknown",
      server_id: "first",
      kill_switch_enabled: true,
    });
    expect(result.current.serverStatus).toBeNull();
    expect(subscriptions[0].stop).toHaveBeenCalledOnce();
    mocked.localStatus.mockResolvedValue({
      ...emptyLocalStatus,
      state: "connected",
      server_id: "first",
    });
    await act(() => result.current.refreshStatus());
    act(() => subscriptions[1].send(reading()));
    expect(result.current.freshness.mode).toBe("live");
  });

  it("ignores messages after unmount", async () => {
    const { unmount, setServers } = await setup();
    unmount();
    act(() => subscriptions[0].send(reading()));
    expect(subscriptions[0].stop).toHaveBeenCalledOnce();
    expect(setServers).not.toHaveBeenCalled();
  });

});
