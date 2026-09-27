import type {
  ConnectionPolicy,
  LocalTunnelStatus,
  ServerStatus,
} from "../../types";
import { protectionEvidence } from "./protectionEvidence";
import { connectionHealth } from "./connectionHealth";

/** Saved choices, runtime configuration, and verified service health are separate facts. */
export function describeConnection(
  local: LocalTunnelStatus,
  serverId: string,
  remote: ServerStatus | null,
  savedPolicy?: ConnectionPolicy,
) {
  const known = local.state !== "unknown";
  const selected = local.server_id === serverId;
  const connected = known && selected && local.state === "connected";
  const other = known && local.server_id !== null && !selected;
  const active = known && selected && local.state !== "disconnected";
  const protectedSession = known && selected && local.kill_switch_enabled;
  const split = local.routing_mode === "selected_routes";
  const applications = local.routing_mode === "selected_applications";
  const android = local.application_routing_backend === "android_packages";
  const recovery = remote?.authorization_recovery;
  const recoveringAuthorization = selected && known && Boolean(recovery && recovery.health !== "healthy");
  const health = connectionHealth({ known, established: connected,
    reconnecting: active && !local.waiting_for_user && (local.recovery_in_progress === true || local.state === "degraded" && local.auto_reconnect_enabled),
    managementAvailable: Boolean(remote), probe: local.transport_quality?.sample });
  const status = !known
    ? "Connection status unknown"
    : recoveringAuthorization ? "Server authorization recovery"
    : active && local.supervisor_status_known === false
      ? "Local monitor unavailable"
      : health.status === "Reconnecting" ? health.status
      : connected
        ? health.status
        : active
          ? local.waiting_for_user
            ? "Waiting for you"
            : local.state === "connecting"
              ? "Connecting"
              : local.auto_reconnect_enabled
                ? "Reconnecting"
                : "Connection interrupted"
          : "Disconnected";
  const action = !known
    ? "Refresh status"
    : active
      ? protectedSession && !android
        ? "Disconnect & release block"
        : "Disconnect"
      : "Connect";
  const routing = !known
    ? "Unknown"
    : !active
      ? "Not active"
      : applications
        ? "Selected applications"
      : split
        ? "Selected routes"
        : local.allow_lan
          ? "Full tunnel · local network allowed"
          : "Full tunnel";
  const enforcementLabels = {
    off: "Disabled",
    armed: "Armed",
    blocking: "Blocking traffic",
    failed: "Enforcement failed",
    unknown: "Status unknown",
  };
  const protection = !known
    ? "Status unknown"
    : other
      ? "See active server"
      : !active
        ? savedPolicy?.kill_switch === true
          ? "Not active · enabled for next connection"
          : savedPolicy?.kill_switch === false
            ? "Disabled"
            : "Not active"
        : local.supervisor_status_known === false
          ? "Status unknown"
          : local.kill_switch_state
            ? enforcementLabels[local.kill_switch_state]
            : protectedSession
              ? "Configured · enforcement unverified"
              : "Disabled";
  const applicationIsolation = applications && active
    ? local.application_routing_ready === true && local.supervisor_status_known === true ? "Verified" : "Not verified"
    : null;
  const evidence = protectionEvidence(local);
  const protectionDetail =
    active && protectedSession && !evidence.verified
      ? "IPv6 verification unavailable"
      : null;
  const summary = !known
    ? "Local tunnel and protection status could not be read. Refresh to verify them."
    : recoveringAuthorization
      ? `${connected ? "The local tunnel is established. " : ""}Server authorization recovery must finish before its data path can be relied on.`
    : active && local.supervisor_status_known === false
      ? "The local connection monitor has not reported recently. Firewall status is unknown; refresh or review the local component in Settings."
      : other
        ? "Another server is active. Open it to inspect or disconnect that tunnel."
        : connected
          ? applications
            ? android
              ? "Applications covered by the active package rules use this tunnel and its DNS. Other apps bypass the VPN or are blocked by Android lockdown."
              : local.application_routing_backend === "windows_bind_redirect"
              ? "Selected Windows executables use this tunnel for new IPv4 TCP and UDP connections. System DNS uses the VPS; other apps keep their usual routes."
              : "New processes launched from SirinVPN use this tunnel and its DNS. Other apps use their normal network."
          : split
            ? "Selected IP ranges and system DNS use this tunnel. Other destinations use your normal network."
            : local.allow_lan
              ? "Internet traffic uses this tunnel. Local network traffic bypasses it."
              : "Internet traffic is routed through this tunnel."
          : active
            ? local.waiting_for_user
              ? android && local.lockdown
                ? "Android keeps traffic blocked. Disconnect ends this VPN session; change Block connections without VPN in Android settings to release its block."
                : local.kill_switch_state === "blocking"
                ? "VPN traffic remains blocked. Reconnect when ready, or Disconnect to release the block."
                : "Automatic recovery is off. Reconnect when ready, or Disconnect to end this session."
              : local.auto_reconnect_enabled
                ? "Trying to restore the connection. Kill switch enforcement is shown below."
                : "Connecting using the selected method. Kill switch enforcement is shown below."
            : "Traffic is not routed through this VPN.";
  const warning =
    recoveringAuthorization
      ? recovery?.containment_verified
        ? "Server authorization recovery is pending. SirinVPN data forwarding is contained; management remains available where possible."
        : "Server authorization enforcement is unavailable. Do not rely on this server until recovery succeeds."
      : android && local.lockdown
        ? "Android Block connections without VPN remains active after Disconnect. Change it in Android VPN settings."
      : active && local.kill_switch_state === "failed"
      ? "The traffic block could not be verified. Do not rely on kill switch protection until this is resolved."
      : connected && applications && local.application_routing_ready !== true
        ? android ? "Android package routing could not be verified. Check the connection before relying on these rules." : "Application routing could not be verified. New launches are disabled."
      : connected && remote && !remote.dns_healthy
        ? "The VPS DNS service is not responding. Run diagnostics."
        : connected && !split && !applications && !local.ipv6_tunneled && !local.ipv6_blocked
          ? "IPv6 routing or blocking could not be established. Check the connection."
          : null;
  return {
    known,
    connected,
    recoveringAuthorization,
    active,
    other,
    status,
    action,
    routing,
    protection,
    applicationIsolation,
    health,
    protectionDetail,
    summary,
    warning,
  };
}
