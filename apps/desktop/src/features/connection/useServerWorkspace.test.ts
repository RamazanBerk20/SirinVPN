import { act, cleanup, renderHook, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { api } from "../../api";
import { emptyLocalStatus } from "../../hooks/useDesktopStatus";
import type { DiagnosticReport, LocalTunnelStatus, ServerProfile } from "../../types";
import { defaultConnectionPreferences } from "./connectionPreferences";
import { useServerWorkspace } from "./useServerWorkspace";
vi.mock("../../api", () => ({
  api: {
    getConnectionPreferences: vi.fn(),
    setConnectionPreferences: vi.fn(),
    keyRotationPending: vi.fn(),
    connectWithPolicy: vi.fn(),
    disconnect: vi.fn(),
    resume: vi.fn(),
    diagnostics: vi.fn(),
  },
}));
const profile = {
  id: "server-a",
  name: "VPS",
  role: "owner",
  administrator: true,
} as ServerProfile;
const input = (localStatus: LocalTunnelStatus = emptyLocalStatus) => ({
  profile,
  localStatus,
  serverStatus: null,
  freshness: {
    refreshing: false,
    updatedAt: null,
    management: "unavailable" as const,
  },
  onRefresh: vi.fn().mockResolvedValue(undefined),
  onAccessChanged: vi.fn().mockResolvedValue(undefined),
  onRemoved: vi.fn().mockResolvedValue(undefined),
});
beforeEach(() => {
  vi.resetAllMocks();
  vi.mocked(api.getConnectionPreferences).mockResolvedValue(
    structuredClone(defaultConnectionPreferences),
  );
  vi.mocked(api.setConnectionPreferences).mockImplementation(async (_, p) =>
    structuredClone(p),
  );
  vi.mocked(api.keyRotationPending).mockResolvedValue(false);
});
afterEach(cleanup);
describe("independent desktop policy", () => {
  it("discards a report closed before the native request finishes", async () => {
    let finish!: (report: DiagnosticReport) => void;
    vi.mocked(api.diagnostics).mockReturnValue(new Promise((resolve) => { finish = resolve; }));
    const { result } = renderHook(() => useServerWorkspace(input()));
    await waitFor(() => expect(result.current.preferences.ready).toBe(true));
    let pending!: Promise<void>;
    act(() => { pending = result.current.runDiagnostics(); });
    expect(api.diagnostics).toHaveBeenCalledWith(profile.id);
    expect(result.current.diagnosticsOpen).toBe(true);
    act(() => result.current.setDiagnosticsOpen(false));
    await act(async () => { finish({ api_version: "v1", checks: [] }); await pending; });
    expect(result.current.diagnostics).toBeNull();
    expect(result.current.diagnosticsOpen).toBe(false);
  });

  it("clears completed diagnostics when the selected server changes", async () => {
    vi.mocked(api.diagnostics).mockResolvedValue({ api_version: "v1", checks: [] });
    const { result, rerender } = renderHook(({ p }) => useServerWorkspace({ ...input(), profile: p }), { initialProps: { p: profile } });
    await waitFor(() => expect(result.current.preferences.ready).toBe(true));
    await act(() => result.current.runDiagnostics());
    expect(result.current.diagnostics).not.toBeNull();
    rerender({ p: { ...profile, id: "another-server" } });
    expect(result.current.diagnostics).toBeNull();
    expect(result.current.diagnosticsOpen).toBe(false);
  });

  for (const kill of [false, true])
    for (const reconnect of [false, true]) {
      it(`saves and connects kill=${kill}, reconnect=${reconnect} without coupling transport or startup`, async () => {
        const { result } = renderHook(() => useServerWorkspace(input()));
        await waitFor(() =>
          expect(result.current.preferences.ready).toBe(true),
        );
        act(() => result.current.setConnectionPolicy("kill_switch", kill));
        act(() =>
          result.current.setConnectionPolicy("automatic_reconnect", reconnect),
        );
        act(() => result.current.setSelectedTransport("tls_like"));
        expect(result.current.connectionPolicy).toEqual({
          kill_switch: kill,
          automatic_reconnect: reconnect,
          connect_on_startup: false,
        });
        expect(api.connectWithPolicy).not.toHaveBeenCalled();
        await act(() => result.current.preferences.save());
        await act(() => result.current.toggle());
        expect(api.connectWithPolicy).toHaveBeenCalledWith(
          profile.id,
          expect.objectContaining({
            transport: "tls_like",
            policy: {
              kill_switch: kill,
              automatic_reconnect: reconnect,
              connect_on_startup: false,
            },
          }),
        );
        expect(api.disconnect).not.toHaveBeenCalled();
      });
    }
  it("resumes the acknowledged active policy even with pending saved changes", async () => {
    const { result } = renderHook(() =>
      useServerWorkspace(
        input({
          ...emptyLocalStatus,
          server_id: profile.id,
          state: "degraded",
          waiting_for_user: true,
          kill_switch_enabled: true,
          auto_reconnect_enabled: false,
          kill_switch_state: "blocking",
        }),
      ),
    );
    await waitFor(() => expect(result.current.preferences.ready).toBe(true));
    act(() => result.current.setConnectionPolicy("connect_on_startup", true));
    await act(() => result.current.resume());
    expect(api.resume).toHaveBeenCalledWith(profile.id);
    expect(api.connectWithPolicy).not.toHaveBeenCalled();
    expect(api.disconnect).not.toHaveBeenCalled();
  });
  it("selecting another server cannot alter an active device policy", async () => {
    const { result, rerender } = renderHook(
      ({ p }) =>
        useServerWorkspace({
          ...input({
            ...emptyLocalStatus,
            server_id: profile.id,
            state: "connected",
            kill_switch_enabled: true,
          }),
          profile: p,
        }),
      { initialProps: { p: profile } },
    );
    await waitFor(() => expect(result.current.preferences.ready).toBe(true));
    rerender({ p: { ...profile, id: "server-b" } });
    await waitFor(() => expect(result.current.preferences.ready).toBe(true));
    await act(() => result.current.toggle());
    expect(api.disconnect).not.toHaveBeenCalled();
    expect(api.connectWithPolicy).not.toHaveBeenCalled();
  });
});
