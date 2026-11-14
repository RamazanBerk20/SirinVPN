// A sample diagnostic report for the demo and the UI audit, as the native diagnostics
// (crates/core/src/diagnostics) send it: English text plus the key the interface translates it by.
const check = (code, label, level, message_key, message, extra = {}) => ({ code, label, level, message, message_key, ...extra });
export function diagnostics(connected) {
  const local = [
    check("local_backend", "Local VPN service", "pass", "local_backend_responded", "The native VPN service responded to the current status request."),
    connected
      ? check("local_tunnel", "Selected VPN connection", "pass", "local_tunnel_connected", "The local VPN service reports an active tunnel for the selected server.")
      : check("local_tunnel", "Selected VPN connection", "warning", "local_tunnel_disconnected", "This device is disconnected. Connect to run current tunnel and server checks."),
    check("local_protection", "Current traffic protection", "warning", "protection_off", "The kill switch is off. Enable it in connection settings if traffic must remain blocked outside the VPN."),
  ];
  if (!connected) return { api_version: "v1", checks: [...local,
    check("local_identity", "Saved management identities", "pass", "local_identity_loaded", "The saved server pin and device certificate/key can be loaded. Their current server authorization is checked over the VPN."),
    check("management", "VPS authentication and connectivity", "warning", "management_disconnected", "Connect this device to the selected server to check authenticated management, current server DNS, VPS networking and traffic leaks. Local checks are available while disconnected."),
  ] };
  return { api_version: "v1", checks: [...local,
    check("local_mtu", "Current path MTU", "warning", "mtu_smaller", "Automatic MTU: 1420 bytes. The path supports a smaller MTU. Review the suggestion in Network settings; automatic application waits for protection and idle conditions.", { message_params: { policy: "automatic", size: "1420" } }),
    check("local_quality", "Current private-tunnel probes", "warning", "quality_unavailable", "No fresh private-tunnel quality sample is available. ICMP filtering can prevent measurement even when the VPN works.", { cause: "not_measured" }),
    check("management", "VPS authentication and connectivity", "pass", "management_accepted", "The private management service accepted the pinned TLS connection and this device's current authorization."),
    check("interface", "VPS VPN interface", "pass", "interface_pass", "The configured VPS VPN interface exists."),
    check("server_cpu", "VPS CPU", "pass", "resource_available", "Current usage: 12%. Capacity is available.", { message_params: { percent: "12" } }),
    check("server_disk", "VPS disk", "warning", "resource_limited", "Current usage: 93%. Capacity is limited. Free resources or increase the VPS capacity.", { message_params: { percent: "93" } }),
    check("dns_resolver_response", "VPS private resolver response", "pass", "dns_valid_time", "Valid DNS response in 28 ms. No query history is retained.", { message_params: { millis: "28" } }),
    check("external_reachability", "Provider firewall and public reachability", "warning", "external_reachability", "Local listeners cannot establish public reachability. If a transport fails, check the VPS provider firewall and configured public ports."),
    check("server_report_format", "VPS diagnostic compatibility", "warning", "report_format", "Some server checks could not be safely interpreted. Use compatible app and server versions and rerun diagnostics."),
    check("leak_ipv4", "IPv4 leak test", "pass", "leak_tunneled", "A request to an internet IPv4 address went through the VPN: your VPS received it from this device's VPN address.", { message_params: { family: "IPv4" } }),
    check("leak_dns", "DNS leak test", "pass", "leak_dns_pass", "A one-off name looked up through this device's normal DNS was answered by your VPS resolver."),
  ] };
}
