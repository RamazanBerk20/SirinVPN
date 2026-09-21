import { describe, expect, it } from "vitest";
import { emptyLocalStatus } from "../../hooks/useDesktopStatus";
import { describeConnection } from "./connectionState";
import { protectionEvidence } from "./protectionEvidence";
import { describeStartup } from "./StartupConnectionState";
import { formatCount, formatTunnelDuration, formatUptime } from "../../format";

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
    expect(protectionEvidence(armed).ipv6).toContain("rules verified");
    expect(protectionEvidence({ ...armed, allow_lan: true }).ipv6).toContain(
      "local network allowed",
    );
    const split = protectionEvidence({
      ...armed,
      ipv6_blocked: false,
      routing_mode: "selected_routes",
    });
    expect(split.ipv6).toContain("other destinations bypass");
    expect(split.detail).toContain("selected routes and DNS");
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
    expect(legacy.protectionDetail).toBe("IPv6 verification unavailable");
    expect(describeConnection(armed, "a", null).protectionDetail).toBeNull();
    expect(
      describeConnection(
        { ...armed, supervisor_status_known: false },
        "a",
        null,
      ).protection,
    ).toBe("Status unknown");
  });
  it("distinguishes saved, effective, unknown and another server's policy", () => {
    expect(
      describeConnection(emptyLocalStatus, "a", null, policy).protection,
    ).toBe("Not active · enabled for next connection");
    expect(
      describeConnection(armed, "a", null, { ...policy, kill_switch: false })
        .protection,
    ).toBe("Armed");
    expect(
      describeConnection({ ...armed, state: "unknown" }, "a", null, policy)
        .protection,
    ).toBe("Status unknown");
    expect(describeConnection(armed, "b", null, policy).protection).toBe(
      "See active server",
    );
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

it("formats short sessions and English counts without changing host uptime or inventing values", () => {
  expect(formatTunnelDuration(24)).toBe("00:24");
  expect(formatTunnelDuration(3601)).toBe("1:00:01");
  expect(formatTunnelDuration(undefined)).toBe("Unavailable");
  expect(formatTunnelDuration(-1)).toBe("Unavailable");
  expect(formatUptime(24)).toBe("0h 0m");
  expect(formatCount(160292)).toBe("160,292");
  expect(formatCount(0)).toBe("0");
  expect(formatCount(undefined)).toBe("Unavailable");
});
