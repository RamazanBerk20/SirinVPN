import type { DiagnosticCheck } from "../types";

/** How a check was established; DiagnosticResults maps each code to its label. */
export type DiagnosticEvidence = "configuration" | "service" | "observed" | "notChecked" | "reported";
export type DiagnosticGroup = "attention" | "review" | "unavailable" | "passed";

const configuration = new Set(["local_identity", "local_routes", "local_ipv6", "interface", "wireguard", "forwarding", "ipv6", "server_routes", "server_firewall", "server_nat4", "server_nat6", "server_ports", "server_mtu"]);
const service = new Set(["local_backend", "local_tunnel", "local_protection", "local_transport", "dns", "server_process", "server_cpu", "server_memory", "server_disk"]);
const unavailable = new Set(["external_reachability", "diagnostics_busy", "dns_probe_busy", "server_report_format"]);

/** Only identify tests implemented by the native diagnostics; green is not proof of leak testing. */
export function diagnosticEvidence(check: DiagnosticCheck): DiagnosticEvidence {
  if (unavailable.has(check.code)) return "notChecked";
  if (check.level === "warning" && (
    /^(No current |No fresh |A current .*unavailable|This current state could not be read)/.test(check.message) ||
    (check.code === "local_mtu" && /Path probing is pending|ICMP probing is unavailable|measurement is incomplete/.test(check.message)) ||
    (["local_dns", "management"].includes(check.code))
  )) return "notChecked";
  if (configuration.has(check.code)) return "configuration";
  if (check.code === "management" && /^The saved (server certificate pin|device management certificate\/key) is invalid\./.test(check.message))
    return "configuration";
  if (service.has(check.code)) return "service";
  if (["local_dns", "management", "local_quality", "local_mtu", "dns_resolver_response"].includes(check.code) ||
      /^dns_(tls_\d+|https_\d+|zone_\d+(?:_\d+)?)$/.test(check.code)) return "observed";
  return "reported";
}

export function diagnosticGroup(check: DiagnosticCheck): DiagnosticGroup {
  if (check.level === "fail") return "attention";
  if (check.level === "pass") return "passed";
  // Public reachability is an explicit qualification to review, not a failed test.
  if (check.code === "external_reachability") return "review";
  return diagnosticEvidence(check) === "notChecked" ? "unavailable" : "review";
}

export function groupDiagnostics(checks: DiagnosticCheck[]) {
  const groups: Record<DiagnosticGroup, DiagnosticCheck[]> = { attention: [], review: [], unavailable: [], passed: [] };
  for (const check of checks) groups[diagnosticGroup(check)].push(check);
  return groups;
}
