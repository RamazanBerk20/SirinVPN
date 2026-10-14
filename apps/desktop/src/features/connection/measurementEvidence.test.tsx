import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, expect, it } from "vitest";
import { emptyLocalStatus } from "../../hooks/useDesktopStatus";
import { DeviceTrafficDetails } from "./DeviceTraffic";
import { currentQualitySample } from "./TransportQuality";
import { describeConnection } from "./connectionState";
import { protectionEvidence } from "./protectionEvidence";
import { MtuDetails, mtuDescription } from "./MtuSettings";
import type { LocalTunnelStatus } from "../../types";
import { t } from "../../i18n";

afterEach(cleanup);
const connected: LocalTunnelStatus = { ...emptyLocalStatus, state: "connected", server_id: "a", transport: "direct_udp", supervisor_status_known: true,
  transport_quality: { selection: "observing", candidates_checked: 1, sample: { transport: "direct_udp", probes_sent: 8, probes_received: 8, latency_micros: 27300, jitter_micros: 2100 } } };

it("uses a validated private-tunnel probe sample only for its connected server and transport", () => {
  expect(currentQualitySample(connected)?.latency_micros).toBe(27300);
  expect(currentQualitySample({ ...connected, transport: "tls_like" })).toBeNull();
  expect(currentQualitySample({ ...connected, state: "disconnected" })).toBeNull();
  expect(currentQualitySample({ ...connected, supervisor_status_known: false })).toBeNull();
  expect(currentQualitySample({ ...connected, transport_quality: { ...connected.transport_quality!, sample: { ...connected.transport_quality!.sample!, probes_sent: 0 } } })).toBeNull();
  const view = render(<DeviceTrafficDetails local={connected} serverId="a" />);
  expect(screen.getByText(t("format.latency", { value: "27.3" }))).toBeTruthy();
  view.rerender(<DeviceTrafficDetails local={connected} serverId="b" />);
  expect(screen.queryByText(t("format.latency", { value: "27.3" }))).toBeNull();
});

it("shows a pending automatic MTU adjustment without claiming it has been applied", () => {
  const mtu = { policy: { mode: "automatic" as const }, configured: 1420, suggested: 1360, outcome: "measured" as const };
  const view = render(<MtuDetails mtu={mtu} />);
  expect(screen.getByText(t("connection.mtu.details.bytes", { value: "1420" }))).toBeTruthy();
  expect(screen.getByText(t("connection.mtu.details.pendingValue", { value: "1360" }))).toBeTruthy();
  view.rerender(<MtuDetails mtu={{ ...mtu, policy: { mode: "manual", value: 1420 } }} />);
  expect(screen.queryByText(t("connection.mtu.details.pending"))).toBeNull();
  expect(mtuDescription({ ...mtu, suggested: null })).not.toContain("null");
});

it("uses Windows executable and system-DNS scope instead of Linux launcher scope", () => {
  const state = describeConnection({ ...connected, routing_mode: "selected_applications", application_routing_backend: "windows_bind_redirect", application_routing_ready: true }, "a", null);
  expect(state.summary).toBe(t("home.summary.windowsApps"));
});

it("reports Android package and OS lockdown evidence without desktop launcher or firewall claims", () => {
  const local: LocalTunnelStatus = { ...connected, routing_mode: "selected_applications", application_routing_backend: "android_packages", application_routing_ready: true, ipv6_blocked: true };
  expect(describeConnection(local, "a", null).summary).toBe(t("home.summary.androidApps"));
  expect(describeConnection(local, "a", null).warning).toBeNull();
  expect(protectionEvidence(local).detail).toBe(t("home.protection.android.packages"));
  expect(protectionEvidence({ ...local, state: "unknown" }).verified).toBe(false);
  expect(protectionEvidence({ ...local, routing_mode: "full_tunnel", lockdown: true }).verified).toBe(true);
  expect(protectionEvidence({ ...local, routing_mode: "full_tunnel", lockdown: false }).verified).toBe(false);
  expect(describeConnection({ ...local, application_routing_ready: false }, "a", null).warning).toBe(t("home.warning.androidAppsUnverified"));
});
