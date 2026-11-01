import type { MessageKey } from "../../i18n";
import type { DiagnosticReport, ServerProfile, TransportPreference } from "../../types";
import { diagnosticGroup } from "../../components/diagnosticEvidence";

export type TroubleshootStatus = "problem" | "check" | "ok";
export type TroubleshootFix = "connectionSettings" | "endpointUpdate" | "repairServer" | "keyRotation" | "restoreDevice";
export interface TroubleshootStep {
  id: "network" | "dns" | "reachability" | "transport" | "clock" | "enrollment" | "membership" | "service";
  status: TroubleshootStatus;
  message: MessageKey;
  fix?: TroubleshootFix;
}

// A failed management check names its cause only in core's fixed text (crates/core/src/diagnostics.rs, management_failure).
const managementCause = {
  clock: /^The private TLS handshake failed\./,
  enrollment: /^(The saved (server certificate pin|device management certificate\/key) is invalid|The VPS rejected device authentication)\./,
  membership: /^The VPS rejected this device's current access\./,
  service: /^The private management (request timed out|connection did not complete)\./,
};

/** The usual causes of a failed connection, in the order to check them, judged only from diagnostic codes and saved settings. */
export function troubleshootSteps({ report, online, profile, transport, rotationPending }: {
  report: DiagnosticReport;
  online: boolean;
  profile: Pick<ServerProfile, "role" | "endpoint" | "tls_like">;
  transport: TransportPreference;
  rotationPending: boolean;
}): TroubleshootStep[] {
  const checks = new Map(report.checks.map((check) => [check.code, check]));
  const failed = (...codes: string[]) => codes.some((code) => { const check = checks.get(code); return check !== undefined && diagnosticGroup(check) === "attention"; });
  const passed = (code: string) => { const check = checks.get(code); return check !== undefined && diagnosticGroup(check) === "passed"; };
  const management = (cause: keyof typeof managementCause) => failed("management") && managementCause[cause].test(checks.get("management")!.message);
  const owner = profile.role === "owner";
  const repair = owner ? "repairServer" as const : undefined;
  // A handshake proves the network, address and method; authenticated management also proves the clock, keys and access.
  const tunnel = passed("local_tunnel");
  const authenticated = passed("management");
  const step = (id: TroubleshootStep["id"], status: TroubleshootStatus, message: MessageKey, fix?: TroubleshootFix): TroubleshootStep =>
    fix ? { id, status, message, fix } : { id, status, message };
  return [
    !online ? step("network", "problem", "help.troubleshoot.network.offline")
      : tunnel ? step("network", "ok", "help.troubleshoot.network.ok")
        : step("network", "check", "help.troubleshoot.network.check"),
    failed("dns", "dns_resolver_response") ? step("dns", "problem", "help.troubleshoot.dns.vps", repair)
      : passed("dns") || passed("dns_resolver_response") ? step("dns", "ok", "help.troubleshoot.dns.ok")
        : /^[\d.]+$|:/.test(profile.endpoint.host) ? step("dns", "ok", "help.troubleshoot.dns.address")
          : step("dns", "check", "help.troubleshoot.dns.check"),
    tunnel ? step("reachability", "ok", "help.troubleshoot.reachability.ok")
      : step("reachability", failed("local_tunnel") && transport === "automatic" ? "problem" : "check", "help.troubleshoot.reachability.check", "endpointUpdate"),
    tunnel ? step("transport", "ok", "help.troubleshoot.transport.ok")
      : transport !== "automatic" ? step("transport", failed("local_tunnel") ? "problem" : "check", "help.troubleshoot.transport.fixed", "connectionSettings")
        : profile.tls_like?.https?.cdn ? step("transport", "check", "help.troubleshoot.transport.automatic")
          : step("transport", "check", owner ? "help.troubleshoot.transport.owner" : "help.troubleshoot.transport.member", repair),
    management("clock") ? step("clock", "problem", "help.troubleshoot.clock.problem")
      : authenticated ? step("clock", "ok", "help.troubleshoot.clock.ok")
        : step("clock", "check", "help.troubleshoot.clock.check"),
    rotationPending ? step("enrollment", "problem", "help.troubleshoot.enrollment.rotation", "keyRotation")
      : failed("local_identity") || management("enrollment") ? step("enrollment", "problem", "help.troubleshoot.enrollment.problem", "restoreDevice")
        : authenticated ? step("enrollment", "ok", "help.troubleshoot.enrollment.ok")
          : step("enrollment", "check", "help.troubleshoot.enrollment.check", "restoreDevice"),
    owner ? step("membership", "ok", "help.troubleshoot.membership.owner")
      : management("membership") ? step("membership", "problem", "help.troubleshoot.membership.problem")
        : authenticated ? step("membership", "ok", "help.troubleshoot.membership.ok")
          : step("membership", "check", "help.troubleshoot.membership.check"),
    failed("server_process", "interface", "wireguard", "server_ports") || management("service") ? step("service", "problem", "help.troubleshoot.service.problem", repair)
      : authenticated ? step("service", "ok", "help.troubleshoot.service.ok")
        : step("service", "check", "help.troubleshoot.service.check", repair),
  ];
}

/** Opens at the first likely cause, else the first step left to check. */
export function firstTroubleshootStep(steps: TroubleshootStep[]): number {
  const index = steps.findIndex((step) => step.status === "problem");
  return index >= 0 ? index : Math.max(0, steps.findIndex((step) => step.status === "check"));
}
