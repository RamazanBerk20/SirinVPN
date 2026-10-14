import { describe, expect, it } from "vitest";
import { emptyLocalStatus } from "../../hooks/useDesktopStatus";
import { describeConnection } from "./connectionState";
import { protectionEvidence } from "./protectionEvidence";
import { describeStartup } from "./StartupConnectionState";
import { formatCount, formatTunnelDuration, formatUptime } from "../../format";
import { t } from "../../i18n";

const policy = {
  kill_switch: true,
  automatic_reconnect: false,
  connect_on_startup: true,
};
const armed = {
  ...emptyLocalStatus,
  state: "connected" as const,
  server_id: "a",
  policy,
  supervisor_status_known: true,
  kill_switch_state: "armed" as const,
  kill_switch_enabled: true,
  ipv6_blocked: true,
};

describe("protection evidence and saved policy", () => {
  it("uses fresh dual-family rule evidence and retains routing exceptions", () => {
    expect(protectionEvidence(armed).verified).toBe(true);
    expect(protectionEvidence(armed).ipv6).toBe(t("home.protection.ipv6.blockedVerified"));
    expect(protectionEvidence({ ...armed, allow_lan: true }).ipv6).toBe(t("home.protection.ipv6.blockedLanAllowed"));
    const split = protectionEvidence({
      ...armed,
      ipv6_blocked: false,
      routing_mode: "selected_routes",
    });
    expect(split.ipv6).toBe(t("home.protection.ipv6.selectedRoutes"));
    expect(split.detail).toBe(t("home.protection.firewall.verifiedSelectedRoutes"));
  });
  it("does not promote stale, legacy, failed or absent evidence into verified IPv6", () => {
    for (const patch of [
      { supervisor_status_known: false },
      { supervisor_status_known: undefined },
      { policy: undefined },
      { kill_switch_state: "failed" as const },
      { state: "unknown" as const },
    ]) {
      expect(protectionEvidence({ ...armed, ...patch }).verified).toBe(false);
    }
    const legacy = describeConnection(
      { ...armed, supervisor_status_known: undefined, policy: undefined },
      "a",
      null,
    );
    expect(legacy.protectionDetail).toBe(t("home.protection.ipv6NotVerified"));
    expect(describeConnection(armed, "a", null).protectionDetail).toBeNull();
    expect(
      describeConnection(
        { ...armed, supervisor_status_known: false },
        "a",
        null,
      ).protectionState,
    ).toBe("unknown");
  });
  it("distinguishes saved, effective, unknown and another server's policy", () => {
    expect(
      describeConnection(emptyLocalStatus, "a", null, policy).protectionState,
    ).toBe("nextConnection");
    expect(
      describeConnection(armed, "a", null, { ...policy, kill_switch: false })
        .protectionState,
    ).toBe("armed");
    expect(
      describeConnection({ ...armed, state: "unknown" }, "a", null, policy)
        .protectionState,
    ).toBe("unknown");
    expect(describeConnection(armed, "b", null, policy).protectionState).toBe("otherServer");
  });
});

it("reports startup service evidence without guessing manual-disconnect history", () => {
  expect(
    describeStartup(
      { ...emptyLocalStatus, startup_service_enabled: false },
      "a",
    ),
  ).toContain("saved, not active");
  expect(
    describeStartup(
      { ...armed, connect_on_startup: true, startup_service_enabled: true },
      "a",
    ),
  ).toContain("active for this server");
  expect(describeStartup(armed, "a")).toContain("unavailable");
  expect(
    describeStartup(
      { ...emptyLocalStatus, startup_service_enabled: true },
      "a",
    ),
  ).toContain("server not confirmed");
  expect(describeStartup(armed, "b")).toContain("Another server");
  expect(describeStartup({ ...armed, state: "unknown" }, "a")).toContain(
    "unknown",
  );
});

it("formats short sessions and counts without inventing values", () => {
  expect(formatTunnelDuration(24)).toBe("00:24");
  expect(formatTunnelDuration(3601)).toBe("1:00:01");
  expect(formatTunnelDuration(undefined)).toBe(t("format.unavailable"));
  expect(formatTunnelDuration(-1)).toBe(t("format.unavailable"));
  expect(formatUptime(24)).toBe("0h 0m");
  expect(formatCount(160292)).toBe("160,292");
  expect(formatCount(0)).toBe("0");
  expect(formatCount(undefined)).toBe(t("format.unavailable"));
});
