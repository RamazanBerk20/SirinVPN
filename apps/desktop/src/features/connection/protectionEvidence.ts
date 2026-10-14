import type { LocalTunnelStatus } from "../../types";
import { t } from "../../i18n";

/** An acknowledged, fresh inet guard covers both IP families, including DNS.
 * A saved flag or an old helper's `ipv6_blocked` flag is not that evidence. */
export function protectionEvidence(local: LocalTunnelStatus) {
  if (local.application_routing_backend === "android_packages") {
    const current = local.state !== "unknown" && local.supervisor_status_known === true;
    const packages = local.routing_mode === "selected_applications";
    const verified = current && (packages ? local.state === "connected" && local.application_routing_ready === true : local.lockdown === true);
    return {
      verified,
      ipv6: t(current && local.ipv6_tunneled ? "home.protection.ipv6.tunneled" : current && local.ipv6_blocked ? "home.protection.ipv6.blocked" : "home.protection.ipv6.unknown"),
      detail: t(!verified ? "home.protection.android.unverified" : packages ? "home.protection.android.packages" : "home.protection.android.lockdown"),
    };
  }
  if (local.routing_mode === "selected_applications") {
    const windows = local.application_routing_backend === "windows_bind_redirect";
    const verified = local.state === "connected" && local.supervisor_status_known === true && local.application_routing_ready === true;
    return {
      verified,
      ipv6: t(!verified ? "home.protection.apps.ipv6Unverified" : local.ipv6_tunneled ? "home.protection.apps.ipv6Tunneled" : "home.protection.apps.ipv6Blocked"),
      detail: t(!verified ? "home.protection.apps.notReady" : windows ? "home.protection.apps.windows" : "home.protection.apps.launched"),
    };
  }
  const verified =
    local.state !== "unknown" &&
    local.supervisor_status_known === true &&
    local.policy?.kill_switch === true &&
    (local.kill_switch_state === "armed" ||
      local.kill_switch_state === "blocking");
  const split = local.routing_mode === "selected_routes";
  const ipv6 = local.ipv6_tunneled
    ? "tunneled"
    : verified && local.ipv6_blocked
      ? local.allow_lan ? "blockedLanAllowed" : "blockedVerified"
      : verified && split
        ? "selectedRoutes"
        : local.ipv6_blocked
          ? "blockedUnverified"
          : split ? "bypassesOutsideRoutes" : "unverified";
  const detail = verified
    ? split ? "verifiedSelectedRoutes" : local.allow_lan ? "verifiedLanAllowed" : "verified"
    : "unverified";
  return { verified, ipv6: t(`home.protection.ipv6.${ipv6}`), detail: t(`home.protection.firewall.${detail}`) };
}
