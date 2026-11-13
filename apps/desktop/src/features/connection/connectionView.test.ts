import { describe, expect, it } from "vitest";
import { emptyLocalStatus } from "../../hooks/useDesktopStatus";
import type { LocalTunnelStatus } from "../../types";
import { connectionView, tunnelReport } from "./connectionView";

const local = (extra: Partial<LocalTunnelStatus>) => ({ ...emptyLocalStatus, server_id: "a", ...extra }) as LocalTunnelStatus;

describe("tunnelReport (the one adapter from native status)", () => {
  it.each([
    [{ kind: "idle" }, {}, "disconnected", false],
    [{ kind: "connecting" }, {}, "connecting", false],
    [{ kind: "connected" }, {}, "connected", true],
    [{ kind: "recovering" }, {}, "reconnecting", false],
    [{ kind: "paused" }, { auto_reconnect_enabled: true }, "waiting_for_user", false],
    [{ kind: "unhealthy", recovering: true }, {}, "reconnecting", false],
    [{ kind: "unhealthy", recovering: false }, { auto_reconnect_enabled: true }, "reconnecting", false],
    [{ kind: "unhealthy", recovering: false }, {}, "interrupted", false],
  ] as const)("phase %o → %s, whatever the old flags say", (phase, extra, expected, established) => {
    // The legacy flags disagree on purpose: the phase wins.
    expect(tunnelReport(local({ state: "unknown", waiting_for_user: false, ...extra, phase } as Partial<LocalTunnelStatus>))).toEqual({ phase: expected, established });
  });

  // Without a phase (an older service), the separate flags still decide.
  it.each([
    [{ state: "unknown" }, "unknown", false],
    [{ state: "disconnected", server_id: null }, "disconnected", false],
    [{ state: "connecting" }, "connecting", false],
    [{ state: "connected" }, "connected", true],
    [{ state: "connected", recovery_in_progress: true }, "reconnecting", true],
    [{ state: "connecting", recovery_in_progress: true }, "reconnecting", false],
    [{ state: "degraded", auto_reconnect_enabled: true }, "reconnecting", false],
    [{ state: "degraded", auto_reconnect_enabled: true, waiting_for_user: true }, "waiting_for_user", false],
    [{ state: "degraded", recovery_in_progress: true, waiting_for_user: true }, "waiting_for_user", false],
    [{ state: "degraded" }, "interrupted", false],
    [{ state: "connected", waiting_for_user: true }, "connected", true],
  ] as const)("%o → %s", (flags, phase, established) => {
    expect(tunnelReport(local(flags as Partial<LocalTunnelStatus>))).toEqual({ phase, established });
  });
});

describe("connectionView", () => {
  const disconnect = { id: 1, kind: "disconnect" as const, serverId: "a" };
  it("maps each tunnel phase of this server", () => {
    expect(connectionView(local({ state: "unknown" }), "a", null)).toEqual({ phase: "unknown" });
    expect(connectionView(local({ state: "disconnected" }), "a", null)).toEqual({ phase: "idle", otherServer: false });
    expect(connectionView(local({ state: "connecting" }), "a", null)).toEqual({ phase: "starting", by: "tunnel" });
    expect(connectionView(local({ state: "connected" }), "a", null)).toEqual({ phase: "up" });
    expect(connectionView(local({ state: "degraded", auto_reconnect_enabled: true }), "a", null)).toEqual({ phase: "reconnecting" });
    expect(connectionView(local({ state: "degraded", waiting_for_user: true }), "a", null)).toEqual({ phase: "interrupted", waitingForUser: true });
    expect(connectionView(local({ state: "degraded" }), "a", null)).toEqual({ phase: "interrupted", waitingForUser: false });
  });
  it("shows another server's tunnel as idle here", () => {
    expect(connectionView(local({ state: "connected" }), "b", null)).toEqual({ phase: "idle", otherServer: true });
  });
  it("lets a pending command win over the reported phase", () => {
    expect(connectionView(local({ state: "connected" }), "a", disconnect)).toEqual({ phase: "stopping" });
    expect(connectionView(local({ state: "unknown" }), "a", disconnect)).toEqual({ phase: "stopping" });
    expect(connectionView(local({ state: "disconnected" }), "a", { id: 2, kind: "connect", serverId: "a" })).toEqual({ phase: "starting", by: "user" });
    expect(connectionView(local({ state: "degraded", waiting_for_user: true }), "a", { id: 3, kind: "resume", serverId: "a" })).toEqual({ phase: "starting", by: "user" });
    // A command for another server leaves this one alone.
    expect(connectionView(local({ state: "connected" }), "a", { ...disconnect, serverId: "b" })).toEqual({ phase: "up" });
  });
  it("applies a server-less disconnect (from a dialog) to the server the tunnel runs", () => {
    const anyServer = { ...disconnect, serverId: null };
    expect(connectionView(local({ state: "connected" }), "a", anyServer)).toEqual({ phase: "stopping" });
    expect(connectionView(local({ state: "connected" }), "b", anyServer)).toEqual({ phase: "idle", otherServer: true });
  });
});
