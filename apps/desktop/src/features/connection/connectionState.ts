import type {
  ConnectionPolicy,
  LocalTunnelStatus,
  ServerStatus,
} from "../../types";
import { protectionEvidence } from "./protectionEvidence";
import { connectionHealth } from "./connectionHealth";
import { t } from "../../i18n";

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
  const statusState = !known
    ? "unknown"
    : recoveringAuthorization ? "restoringAccess"
    : active && local.supervisor_status_known === false
      ? "monitorUnavailable"
      : health.state === "reconnecting" ? "reconnecting"
      : connected
        ? health.state
        : active
          ? local.waiting_for_user
            ? "interrupted"
            : local.state === "connecting"
              ? "connecting"
              : local.auto_reconnect_enabled
                ? "reconnecting"
                : "interrupted"
          : "disconnected";
  const actionState = !known
    ? "refresh"
    : active
      ? protectedSession && !android ? "disconnectAndUnblock" : "disconnect"
      : "connect";
  const routingState = !known
    ? "unknown"
    : !active
      ? "inactive"
      : applications
        ? "selectedApps"
      : split
        ? "selectedRoutes"
        : local.allow_lan
          ? "fullTunnelLan"
          : "fullTunnel";
  const protectionState = !known
    ? "unknown"
    : other
      ? "otherServer"
      : !active
        ? savedPolicy?.kill_switch === true
          ? "nextConnection"
          : savedPolicy?.kill_switch === false
            ? "off"
            : "inactive"
        : local.supervisor_status_known === false
          ? "unknown"
          : local.kill_switch_state
            ? local.kill_switch_state
            : protectedSession
              ? "unverified"
              : "off";
  const applicationIsolation = applications && active
    ? t(local.application_routing_ready === true && local.supervisor_status_known === true ? "home.isolation.verified" : "home.isolation.unverified")
    : null;
  const evidence = protectionEvidence(local);
  const protectionDetail =
    active && protectedSession && !evidence.verified
      ? t("home.protection.ipv6NotVerified")
      : null;
  const summaryState = !known
    ? "unknown"
    : recoveringAuthorization
      ? "restoringAccess"
    : active && local.supervisor_status_known === false
      ? "monitorUnavailable"
      : other
        ? "otherServer"
        : connected
          ? applications
            ? android
              ? "androidApps"
              : local.application_routing_backend === "windows_bind_redirect"
              ? "windowsApps"
              : "launchedApps"
          : split
            ? "selectedRoutes"
            : local.allow_lan
              ? "fullTunnelLan"
              : "fullTunnel"
          : active
            ? local.waiting_for_user
              ? android && local.lockdown
                ? "waitingAndroidLockdown"
                : local.kill_switch_state === "blocking"
                ? "waitingBlocked"
                : "waiting"
              : local.auto_reconnect_enabled
                ? "reconnecting"
                : "connecting"
            : "disconnected";
  const warningState =
    recoveringAuthorization
      ? recovery?.containment_verified ? "accessContained" : "accessUnenforced"
      : android && local.lockdown
        ? "androidLockdown"
      : active && local.kill_switch_state === "failed"
      ? "killSwitchFailed"
      : connected && applications && local.application_routing_ready !== true
        ? android ? "androidAppsUnverified" : "appsUnverified"
      : connected && remote && !remote.dns_healthy
        ? "dnsDown"
        : connected && !split && !applications && !local.ipv6_tunneled && !local.ipv6_blocked
          ? "ipv6"
          : null;
  return {
    known,
    connected,
    recoveringAuthorization,
    active,
    other,
    statusState,
    status: t(`home.status.${statusState}`),
    actionState,
    action: t(`home.action.${actionState}`),
    routing: t(`home.routing.${routingState}`),
    protectionState,
    protection: t(`home.killSwitch.${protectionState}`),
    applicationIsolation,
    health,
    protectionDetail,
    summary: t(`home.summary.${summaryState}`),
    warning: warningState && t(`home.warning.${warningState}`),
  };
}
