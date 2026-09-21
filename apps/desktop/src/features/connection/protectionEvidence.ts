import type { LocalTunnelStatus } from "../../types";

/** An acknowledged, fresh inet guard covers both IP families, including DNS.
 * A saved flag or an old helper's `ipv6_blocked` flag is not that evidence. */
export function protectionEvidence(local: LocalTunnelStatus) {
  if (local.application_routing_backend === "android_packages") {
    const current = local.state !== "unknown" && local.supervisor_status_known === true;
    const packages = local.routing_mode === "selected_applications";
    const verified = current && (packages ? local.state === "connected" && local.application_routing_ready === true : local.lockdown === true);
    return {
      verified,
      ipv6: current && local.ipv6_tunneled ? "IPv6 tunnel configured" : current && local.ipv6_blocked ? "IPv6 containment route configured" : "IPv6 configuration unavailable",
      detail: !verified ? "Android routing or traffic-blocking evidence is unavailable."
        : packages ? "Android applies the active package rules to traffic and DNS. Excluded apps bypass the VPN unless Android lockdown blocks them."
        : "Android reports Block connections without VPN enabled. Android enforces this policy, including for excluded apps.",
    };
  }
  if (local.routing_mode === "selected_applications") {
    const windows = local.application_routing_backend === "windows_bind_redirect";
    const verified = local.state === "connected" && local.supervisor_status_known === true && local.application_routing_ready === true;
    return {
      verified,
      ipv6: verified ? local.ipv6_tunneled ? "Launched apps: IPv6 tunnel configured" : "Launched apps: IPv6 blocked" : "Application routing verification unavailable",
      detail: verified ? windows ? "Selected executables use the VPN for IPv4 TCP/UDP; IPv6 is blocked. System DNS uses the VPS. Other applications keep their usual routes."
        : "Traffic and DNS from launched processes use the VPN. Other apps keep their usual network settings." : "The application tunnel is not ready. New launches are disabled.",
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
    ? "Tunnel routing configured"
    : verified && local.ipv6_blocked
      ? local.allow_lan
        ? "Internet IPv6 blocked · local network allowed"
        : "Blocked · firewall rules verified"
      : verified && split
        ? "Selected routes guarded · other destinations bypass"
        : local.ipv6_blocked
          ? "Block configured · enforcement unverified"
          : split
            ? "Other IPv6 destinations bypass the tunnel"
            : "Not verified";
  const detail = verified
    ? split
      ? "IPv4/IPv6 rules verified for selected routes and DNS. Other destinations bypass the VPN."
      : local.allow_lan
        ? "IPv4, IPv6 and DNS firewall rules verified. Local network access remains allowed."
        : "IPv4, IPv6 and DNS firewall rules verified."
    : "Firewall enforcement could not be verified. IPv6 verification is unavailable.";
  return { verified, ipv6, detail };
}
