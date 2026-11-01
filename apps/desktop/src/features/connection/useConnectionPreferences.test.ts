import { act, renderHook, waitFor, cleanup } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { api } from "../../api";
import { invoke } from "../../platform";
vi.mock("../../platform", () => ({ invoke: vi.fn() }));
import {
  defaultConnectionPreferences as defaults,
  preferenceDifferences,
} from "./connectionPreferences";
import { useConnectionPreferences } from "./useConnectionPreferences";
import { emptyLocalStatus } from "../../hooks/useDesktopStatus";
import { t } from "../../i18n";
import { formatTransport } from "../../format";
vi.mock("../../api", () => ({
  api: { getConnectionPreferences: vi.fn(), setConnectionPreferences: vi.fn() },
}));
beforeEach(() => {
  vi.resetAllMocks();
  vi.mocked(api.getConnectionPreferences).mockResolvedValue(defaults);
});
afterEach(cleanup);
describe("saved connection preferences", () => {
  it("treats a reverted optional field as unchanged", async () => {
    const { result } = renderHook(() => useConnectionPreferences("a"));
    await waitFor(() => expect(result.current.ready).toBe(true));
    act(() => result.current.change({ manual_mtu: 1400 }));
    expect(result.current.dirty).toBe(true);
    act(() => result.current.change({ manual_mtu: null, android_applications: null }));
    expect(result.current.dirty).toBe(false);
  });
  it("does not report ranges kept from Selected routes mode as unsaved in another mode", async () => {
    vi.mocked(api.getConnectionPreferences).mockResolvedValue({ ...defaults, routing: { mode: "full_tunnel", included_routes: ["198.51.100.0/24"], allow_lan: false } });
    const { result } = renderHook(() => useConnectionPreferences("a"));
    await waitFor(() => expect(result.current.ready).toBe(true));
    expect(result.current.dirty).toBe(false);
  });
  it("saves complete server-scoped preferences and reloads them after remount", async () => {
    const data = new Map();
    vi.mocked(api.getConnectionPreferences).mockImplementation(
      async (id) => data.get(id) ?? defaults,
    );
    vi.mocked(api.setConnectionPreferences).mockImplementation(
      async (id, preferences) => {
        data.set(id, preferences);
        return preferences;
      },
    );
    const { result, rerender, unmount } = renderHook(
      ({ id }) => useConnectionPreferences(id),
      { initialProps: { id: "a" } },
    );
    await waitFor(() => expect(result.current.ready).toBe(true));
    act(() => {
      result.current.change({
        transport: "direct_udp",
        policy: {
          kill_switch: true,
          automatic_reconnect: true,
          connect_on_startup: true,
        },
      });
      result.current.route({ mode: "selected_routes", allow_lan: true });
      result.current.setRoutesText("198.51.100.0/24\n203.0.113.0/24");
    });
    expect(result.current.dirty).toBe(true);
    await act(() => result.current.save());
    expect(result.current.saved?.routing.included_routes).toHaveLength(2);
    rerender({ id: "b" });
    await waitFor(() =>
      expect(result.current.saved?.transport).toBe("automatic"),
    );
    unmount();
    const reopened = renderHook(() => useConnectionPreferences("a"));
    await waitFor(() =>
      expect(reopened.result.current.saved?.transport).toBe("direct_udp"),
    );
    expect(reopened.result.current.saved?.policy.kill_switch).toBe(true);
    expect(reopened.result.current.dirty).toBe(false);
  });
  it("retains the last saved configuration and the user's draft after a failed save", async () => {
    vi.mocked(api.setConnectionPreferences).mockRejectedValue(
      new Error("Disk full"),
    );
    const { result } = renderHook(() => useConnectionPreferences("a"));
    await waitFor(() => expect(result.current.ready).toBe(true));
    act(() => result.current.change({ transport: "direct_udp" }));
    await act(() => result.current.save());
    expect(result.current.error).toContain("Disk full");
    expect(result.current.saved?.transport).toBe("automatic");
    expect(result.current.draft.transport).toBe("direct_udp");
    expect(result.current.dirty).toBe(true);
    act(() => result.current.discard());
    expect(result.current.dirty).toBe(false);
  });
  it("does not replace another server's preferences with a late response", async () => {
    let resolve!: (value: typeof defaults) => void;
    vi.mocked(api.getConnectionPreferences).mockImplementation((id) =>
      id === "a"
        ? new Promise((r) => {
            resolve = r;
          })
        : Promise.resolve(defaults),
    );
    const { result, rerender } = renderHook(
      ({ id }) => useConnectionPreferences(id),
      { initialProps: { id: "a" } },
    );
    rerender({ id: "b" });
    await waitFor(() => expect(result.current.ready).toBe(true));
    await act(async () => resolve({ ...defaults, transport: "tls_like" }));
    expect(result.current.saved?.transport).toBe("automatic");
  });
  it("compares known runtime configuration without treating Automatic as an effective transport", () => {
    const local = {
      ...emptyLocalStatus,
      state: "connected" as const,
      server_id: "a",
      transport: "direct_udp" as const,
      included_routes: [],
    };
    expect(preferenceDifferences(defaults, local, "a")).toEqual([]);
    expect(
      preferenceDifferences(
        { ...defaults, transport: "tcp_fallback" },
        local,
        "a",
      ),
    ).toEqual([t("connection.differences.method", { method: formatTransport("direct_udp") })]);
    expect(
      preferenceDifferences(
        {
          ...defaults,
          policy: {
            kill_switch: true,
            automatic_reconnect: true,
            connect_on_startup: true,
          },
        },
        { ...local, state: "unknown" },
        "a",
      ),
    ).toEqual([]);
  });
});

it("saves the Android reconnect switch immediately without saving incomplete drafts", async () => {
  const enabled = { ...defaults, policy: { ...defaults.policy, automatic_reconnect: true } };
  vi.mocked(api.getConnectionPreferences).mockResolvedValue(enabled);
  vi.mocked(invoke).mockResolvedValue(defaults);
  const { result } = renderHook(() => useConnectionPreferences("a"));
  await waitFor(() => expect(result.current.ready).toBe(true));
  act(() => {
    result.current.change({ transport: "tls_like" });
    result.current.route({ mode: "selected_routes" });
    result.current.setRoutesText("unfinished route");
  });
  await act(() => result.current.setReconnect(false));
  expect(invoke).toHaveBeenCalledWith("android_set_reconnect", { serverId: "a", enabled: false });
  expect(api.setConnectionPreferences).not.toHaveBeenCalled();
  expect(result.current.saved?.policy.automatic_reconnect).toBe(false);
  expect(result.current.draft.policy.automatic_reconnect).toBe(false);
  expect(result.current.draft.transport).toBe("tls_like");
  expect(result.current.routesText).toBe("unfinished route");
  expect(result.current.dirty).toBe(true);
});

it("keeps the confirmed reconnect value after a rejected Android switch change", async () => {
  const enabled = { ...defaults, policy: { ...defaults.policy, automatic_reconnect: true } };
  vi.mocked(api.getConnectionPreferences).mockResolvedValue(enabled);
  vi.mocked(invoke).mockRejectedValue(new Error("Could not save preference"));
  const { result } = renderHook(() => useConnectionPreferences("a"));
  await waitFor(() => expect(result.current.ready).toBe(true));
  await act(() => result.current.setReconnect(false));
  expect(result.current.draft.policy.automatic_reconnect).toBe(true);
  expect(result.current.saved?.policy.automatic_reconnect).toBe(true);
  expect(result.current.error).toContain("Could not save preference");
});

it("does not apply a late reconnect response to another Android server", async () => {
  let finish!: (value: typeof defaults) => void;
  vi.mocked(invoke).mockImplementation(() => new Promise(resolve => { finish = resolve; }));
  const { result, rerender } = renderHook(({ id }) => useConnectionPreferences(id), { initialProps: { id: "a" } });
  await waitFor(() => expect(result.current.ready).toBe(true));
  let pending: Promise<void>;
  act(() => { pending = result.current.setReconnect(true); });
  rerender({ id: "b" });
  await waitFor(() => expect(result.current.ready).toBe(true));
  await act(async () => {
    finish({ ...defaults, policy: { ...defaults.policy, automatic_reconnect: true } });
    await pending;
  });
  expect(result.current.saved?.policy.automatic_reconnect).toBe(false);
  expect(result.current.draft.policy.automatic_reconnect).toBe(false);
});

it("accepts a manual MTU limited by Obfuscated UDP as the saved value", () => {
  const local = {
    ...emptyLocalStatus,
    state: "connected" as const,
    server_id: "a",
    transport: "obfuscated_udp" as const,
    mtu: { policy: { mode: "manual" as const, value: 1398 }, configured: 1398, suggested: null, outcome: "pending" as const },
  };
  const saved = { ...defaults, manual_mtu: 1420 };
  expect(preferenceDifferences(saved, local, "a")).toEqual([]);
  const manual1398 = t("connection.differences.mtu.manual", { value: "1398" });
  expect(preferenceDifferences(saved, { ...local, transport: "direct_udp" }, "a")).toEqual([manual1398]);
  expect(preferenceDifferences({ ...defaults, manual_mtu: 1300 }, local, "a")).toEqual([manual1398]);
});
