import { describe, expect, it } from "vitest";
import { emptyLocalStatus } from "../../hooks/useDesktopStatus";
import type { ServerStatus } from "../../types";
import { describeConnection } from "./connectionState";
const connected = {
  ...emptyLocalStatus,
  state: "connected" as const,
  server_id: "a",
  ipv6_blocked: true,
};
describe("operational connection states", () => {
  it("reports authorization recovery independently from an established tunnel", () => {
    const remote = { authorization_recovery: { health: "recovery_failed", generation: 4, committed: true, containment_verified: false } } as ServerStatus;
    const state = describeConnection(connected, "a", remote);
    expect(state.connected).toBe(true);
    expect(state.status).toBe("Server authorization recovery");
    expect(state.warning).toContain("enforcement is unavailable");
    expect(state.recoveringAuthorization).toBe(true);
    expect(state.summary).toContain("must finish");
    for (const state of ["connecting", "degraded", "disconnected"] as const) {
      expect(describeConnection({ ...connected, state }, "a", remote).summary).not.toContain("tunnel is established");
    }
    expect(describeConnection(connected, "another", remote).recoveringAuthorization).toBe(false);
  });
  it("does not promise to release Android lockdown on disconnect", () => {
    const state = describeConnection({ ...connected, application_routing_backend: "android_packages", kill_switch_enabled: true, lockdown: true }, "a", null);
    expect(state.action).toBe("Disconnect");
    expect(state.warning).toContain("remains active after Disconnect");
  });
  it("reports application scope independently of the optional host kill switch", () => {
    const local = { ...connected, routing_mode: "selected_applications" as const, ipv6_blocked: false,
      application_routing_ready: true, supervisor_status_known: true, kill_switch_enabled: false };
    const state = describeConnection(local, "a", null);
    expect(state.routing).toBe("Selected applications");
    expect(state.protection).toBe("Disabled");
    expect(state.applicationIsolation).toBe("Verified");
    expect(state.summary).toContain("Other apps use their normal network");
    expect(state.warning).toBeNull();
    expect(describeConnection({ ...local, application_routing_ready: false }, "a", null).warning).toContain("New launches are disabled");
  });
  it("keeps local VPN connectivity when management is unavailable", () => {
    const state = describeConnection(connected, "a", null);
    expect(state.status).toBe("Connected");
    expect(state.action).toBe("Disconnect");
    expect(state.summary).toContain("routed through this tunnel");
  });
  it("never interprets stale protection flags as verified after a local failure", () => {
    for (const flag of [true, false]) {
      const state = describeConnection(
        { ...connected, state: "unknown", kill_switch_enabled: flag },
        "a",
        null,
      );
      expect(state.protection).toBe("Status unknown");
      expect(state.action).toBe("Refresh status");
      expect(state.active).toBe(false);
    }
  });
  it("distinguishes protection configuration from firewall enforcement and drafts", () => {
    const reconnect = describeConnection(
      {
        ...connected,
        state: "degraded",
        kill_switch_enabled: true,
        auto_reconnect_enabled: true,
      },
      "a",
      null,
    );
    expect(reconnect.status).toBe("Reconnecting");
    expect(reconnect.protection).toContain("enforcement unverified");
    expect(reconnect.action).toBe("Disconnect & release block");
    expect(describeConnection(emptyLocalStatus, "a", null).protection).toBe(
      "Not active",
    );
  });
  it("keeps routing scope and DNS failures visible", () => {
    const state = describeConnection(
      { ...connected, routing_mode: "selected_routes" },
      "a",
      { dns_healthy: false } as ServerStatus,
    );
    expect(state.summary).toContain(
      "Other destinations use your normal network",
    );
    expect(state.warning).toContain("DNS service is not responding");
  });
  it("does not confuse selecting another server with connecting to it", () => {
    const state = describeConnection(connected, "b", null);
    expect(state.status).toBe("Disconnected");
    expect(state.other).toBe(true);
    expect(state.protection).toBe("See active server");
  });
});

it("reports verified, failed, unknown, and waiting protection without inferring retries", () => {
  for (const [effective, label] of [
    ["armed", "Armed"],
    ["blocking", "Blocking traffic"],
    ["failed", "Enforcement failed"],
    ["unknown", "Status unknown"],
    ["off", "Disabled"],
  ] as const) {
    const state = describeConnection(
      {
        ...connected,
        state: "degraded",
        waiting_for_user: true,
        kill_switch_enabled: true,
        auto_reconnect_enabled: false,
        kill_switch_state: effective,
      },
      "a",
      null,
    );
    expect(state.protection).toBe(label);
    expect(state.status).toBe("Waiting for you");
    expect(state.action).toBe("Disconnect & release block");
  }
  const stale = describeConnection(
    {
      ...connected,
      state: "degraded",
      supervisor_status_known: false,
      auto_reconnect_enabled: true,
      kill_switch_state: "unknown",
    },
    "a",
    null,
  );
  expect(stale.status).toBe("Local monitor unavailable");
});
