import { describe, expect, it } from "vitest";
import { emptyLocalStatus } from "../../hooks/useDesktopStatus";
import type { ServerStatus } from "../../types";
import { describeConnection } from "./connectionState";
import { t } from "../../i18n";
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
    expect(state.statusState).toBe("restoringAccess");
    expect(state.warning).toBe(t("home.warning.accessUnenforced"));
    expect(state.recoveringAuthorization).toBe(true);
    expect(state.summary).toBe(t("home.summary.restoringAccess"));
    for (const state of ["connecting", "degraded", "disconnected"] as const) {
      expect(describeConnection({ ...connected, state }, "a", remote).summary).toBe(t("home.summary.restoringAccess"));
    }
    expect(describeConnection(connected, "another", remote).recoveringAuthorization).toBe(false);
  });
  it("does not promise to release Android lockdown on disconnect", () => {
    const state = describeConnection({ ...connected, application_routing_backend: "android_packages", kill_switch_enabled: true, lockdown: true }, "a", null);
    expect(state.actionState).toBe("disconnect");
    expect(state.warning).toBe(t("home.warning.androidLockdown"));
  });
  it("reports application scope independently of the optional host kill switch", () => {
    const local = { ...connected, routing_mode: "selected_applications" as const, ipv6_blocked: false,
      application_routing_ready: true, supervisor_status_known: true, kill_switch_enabled: false };
    const state = describeConnection(local, "a", null);
    expect(state.routing).toBe(t("home.routing.selectedApps"));
    expect(state.protectionState).toBe("off");
    expect(state.applicationIsolation).toBe(t("home.isolation.verified"));
    expect(state.summary).toBe(t("home.summary.launchedApps"));
    expect(state.warning).toBeNull();
    expect(describeConnection({ ...local, application_routing_ready: false }, "a", null).warning).toBe(t("home.warning.appsUnverified"));
  });
  it("keeps local VPN connectivity when management is unavailable", () => {
    const state = describeConnection(connected, "a", null);
    expect(state.statusState).toBe("connected");
    expect(state.actionState).toBe("disconnect");
    expect(state.summary).toBe(t("home.summary.fullTunnel"));
  });
  it("never interprets stale protection flags as verified after a local failure", () => {
    for (const flag of [true, false]) {
      const state = describeConnection(
        { ...connected, state: "unknown", kill_switch_enabled: flag },
        "a",
        null,
      );
      expect(state.protectionState).toBe("unknown");
      expect(state.actionState).toBe("refresh");
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
    expect(reconnect.statusState).toBe("reconnecting");
    expect(reconnect.protectionState).toBe("unverified");
    expect(reconnect.actionState).toBe("disconnectAndUnblock");
    expect(describeConnection(emptyLocalStatus, "a", null).protectionState).toBe("inactive");
  });
  it("keeps routing scope and DNS failures visible", () => {
    const state = describeConnection(
      { ...connected, routing_mode: "selected_routes" },
      "a",
      { dns_healthy: false } as ServerStatus,
    );
    expect(state.summary).toBe(t("home.summary.selectedRoutes"));
    expect(state.warning).toBe(t("home.warning.dnsDown"));
  });
  it("does not confuse selecting another server with connecting to it", () => {
    const state = describeConnection(connected, "b", null);
    expect(state.statusState).toBe("disconnected");
    expect(state.other).toBe(true);
    expect(state.protectionState).toBe("otherServer");
  });
});

it("reports verified, failed, unknown, and waiting protection without inferring retries", () => {
  for (const effective of ["armed", "blocking", "failed", "unknown", "off"] as const) {
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
    expect(state.protectionState).toBe(effective);
    expect(state.statusState).toBe("interrupted");
    expect(state.actionState).toBe("disconnectAndUnblock");
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
  expect(stale.statusState).toBe("monitorUnavailable");
});
