import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, expect, it } from "vitest";
import { emptyLocalStatus } from "../../hooks/useDesktopStatus";
import { DeviceTrafficDetails } from "./DeviceTraffic";
import { currentQualitySample } from "./TransportQuality";
import { describeConnection } from "./connectionState";
import { protectionEvidence } from "./protectionEvidence";
import { MtuDetails, mtuDescription } from "./MtuSettings";
import type { LocalTunnelStatus } from "../../types";

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
  expect(screen.getByText("27.3 ms")).toBeTruthy();
  view.rerender(<DeviceTrafficDetails local={connected} serverId="b" />);
  expect(screen.queryByText("27.3 ms")).toBeNull();
});

it("shows a pending automatic MTU adjustment without claiming it has been applied", () => {
  const mtu = { policy: { mode: "automatic" as const }, configured: 1420, suggested: 1360, outcome: "measured" as const };
  const view = render(<MtuDetails mtu={mtu} />);
  expect(screen.getByText("1420 bytes")).toBeTruthy();
  expect(screen.getByText("1360 bytes · waiting for protection and idle traffic")).toBeTruthy();
  view.rerender(<MtuDetails mtu={{ ...mtu, policy: { mode: "manual", value: 1420 } }} />);
  expect(screen.queryByText("Pending change")).toBeNull();
  expect(mtuDescription({ ...mtu, suggested: null })).not.toContain("null");
});

it("uses Windows executable and system-DNS scope instead of Linux launcher scope", () => {
  const state = describeConnection({ ...connected, routing_mode: "selected_applications", application_routing_backend: "windows_bind_redirect", application_routing_ready: true }, "a", null);
  expect(state.summary).toContain("Selected Windows executables");
  expect(state.summary).toContain("System DNS uses the VPS");
  expect(state.summary).not.toContain("New processes launched from SirinVPN");
});

it("reports Android package and OS lockdown evidence without desktop launcher or firewall claims", () => {
  const local: LocalTunnelStatus = { ...connected, routing_mode: "selected_applications", application_routing_backend: "android_packages", application_routing_ready: true, ipv6_blocked: true };
  expect(describeConnection(local, "a", null).summary).toContain("active package rules");
  expect(describeConnection(local, "a", null).warning).toBeNull();
  expect(protectionEvidence(local).detail).toContain("Android");
  expect(protectionEvidence({ ...local, state: "unknown" }).verified).toBe(false);
  expect(protectionEvidence({ ...local, routing_mode: "full_tunnel", lockdown: true }).verified).toBe(true);
  expect(protectionEvidence({ ...local, routing_mode: "full_tunnel", lockdown: false }).verified).toBe(false);
  expect(describeConnection({ ...local, application_routing_ready: false }, "a", null).warning).not.toContain("launches");
});
