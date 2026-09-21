import type {
  LocalTunnelStatus,
  ConnectionPolicy,
  NetworkProfile,
  TransportPreference,
  TunnelRoutingPolicy,
} from "../../types";
import { formatTransport } from "../../format";

export interface ConnectionPreferences {
  android_applications?: { mode: "all" | "include" | "exclude"; packages: string[] } | null;
  manual_mtu?: number | null;
  transport: TransportPreference;
  network_profile: NetworkProfile;
  policy: ConnectionPolicy;
  routing: TunnelRoutingPolicy;
}
export const defaultConnectionPreferences: ConnectionPreferences = {
  transport: "automatic",
  network_profile: "automatic",
  policy: {
    kill_switch: false,
    automatic_reconnect: false,
    connect_on_startup: false,
  },
  routing: { mode: "full_tunnel", included_routes: [], allow_lan: false },
};

export function preferenceDifferences(
  saved: ConnectionPreferences,
  local: LocalTunnelStatus,
  serverId: string,
): string[] {
  if (
    local.server_id !== serverId ||
    local.state === "disconnected" ||
    local.state === "unknown"
  )
    return [];
  const differences: string[] = [];
  if (local.mtu && (saved.manual_mtu ?? null) !== (local.mtu.policy.mode === "manual" ? local.mtu.policy.value : null)) differences.push(`MTU: ${local.mtu.configured} (${local.mtu.policy.mode})`);
  // Automatic is a selection policy, not the transport that happened to win.
  if (
    saved.transport !== "automatic" &&
    local.transport &&
    saved.transport !== local.transport
  )
    differences.push(`Transport: ${formatTransport(local.transport)}`);
  for (const [key, actual, label] of [
    ["kill_switch", local.kill_switch_enabled, "Kill switch"],
    [
      "automatic_reconnect",
      local.auto_reconnect_enabled,
      "Automatic reconnect",
    ],
    [
      "connect_on_startup",
      local.connect_on_startup,
      "Connect on system startup",
    ],
  ] as const) {
    if (actual !== undefined && saved.policy[key] !== actual)
      differences.push(`${label}: ${actual ? "on" : "off"}`);
  }
  if (local.routing_mode && saved.routing.mode !== local.routing_mode)
    differences.push(
      `Routing: ${local.routing_mode === "full_tunnel" ? "full tunnel" : local.routing_mode === "selected_applications" ? "selected applications" : "selected routes"}`,
    );
  if (
    local.allow_lan !== undefined &&
    saved.routing.allow_lan !== local.allow_lan
  )
    differences.push(`Local network bypass: ${local.allow_lan ? "on" : "off"}`);
  if (
    saved.routing.mode === "selected_routes" &&
    local.routing_mode === "selected_routes" &&
    local.included_routes &&
    [...saved.routing.included_routes].sort().join(",") !==
      [...local.included_routes].sort().join(",")
  )
    differences.push("Selected IP ranges differ");
  return differences;
}
