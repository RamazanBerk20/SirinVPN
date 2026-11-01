import type {
  LocalTunnelStatus,
  ConnectionPolicy,
  NetworkProfile,
  TransportPreference,
  TunnelRoutingPolicy,
} from "../../types";
import { formatTransport } from "../../format";
import { formatNumber, t } from "../../i18n";

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

// Obfuscated UDP and QUIC limit a manual MTU to these values; Android reports the limited value.
export const OBFUSCATED_UDP_MAX_MTU = 1398;
export const QUIC_MAX_MTU = 1380;

/** MTU values are technical sizes: localized digits, but no thousands separator. */
export function formatMtu(value: number): string {
  return formatNumber(value, { useGrouping: false });
}

function manualMtuMatches(saved: number | null, local: LocalTunnelStatus): boolean {
  const actual = local.mtu?.policy.mode === "manual" ? local.mtu.policy.value : null;
  return (
    saved === actual ||
    (saved !== null &&
      ((local.transport === "obfuscated_udp" && actual === Math.min(saved, OBFUSCATED_UDP_MAX_MTU)) ||
        (local.transport === "quic" && actual === Math.min(saved, QUIC_MAX_MTU))))
  );
}

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
  if (local.mtu && !manualMtuMatches(saved.manual_mtu ?? null, local))
    differences.push(t(`connection.differences.mtu.${local.mtu.policy.mode}`, { value: formatMtu(local.mtu.configured) }));
  // Automatic is a selection policy, not the transport that happened to win.
  if (
    saved.transport !== "automatic" &&
    local.transport &&
    saved.transport !== local.transport
  )
    differences.push(t("connection.differences.method", { method: formatTransport(local.transport) }));
  // On Android the system owns blocking and startup, and automatic reconnect applies at once: none waits for a reconnect.
  const android = local.application_routing_backend === "android_packages";
  for (const [key, actual] of android ? [] : [
    ["kill_switch", local.kill_switch_enabled],
    ["automatic_reconnect", local.auto_reconnect_enabled],
    ["connect_on_startup", local.connect_on_startup],
  ] as const) {
    if (actual !== undefined && saved.policy[key] !== actual)
      differences.push(t(`connection.differences.policy.${key}.${actual ? "on" : "off"}`));
  }
  if (local.routing_mode && saved.routing.mode !== local.routing_mode)
    differences.push(t(`connection.differences.routing.${local.routing_mode}`));
  if (
    local.allow_lan !== undefined &&
    saved.routing.allow_lan !== local.allow_lan
  )
    differences.push(t(`connection.differences.localNetwork.${local.allow_lan ? "on" : "off"}`));
  if (
    saved.routing.mode === "selected_routes" &&
    local.routing_mode === "selected_routes" &&
    local.included_routes &&
    [...saved.routing.included_routes].sort().join(",") !==
      [...local.included_routes].sort().join(",")
  )
    differences.push(t("connection.differences.routes"));
  return differences;
}
