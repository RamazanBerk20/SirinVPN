import { describe, expect, it } from "vitest";
import type { DiagnosticCheck } from "../../types";
import { firstTroubleshootStep, troubleshootSteps } from "./troubleshooting";

// The wizard reads the management failure's cause from core's text; this pins it to the real messages.
const core = Object.values(import.meta.glob<string>("../../../../../crates/core/src/diagnostics.rs", { query: "?raw", import: "default", eager: true }))[0];
const check = (code: string, level: DiagnosticCheck["level"], message = "Fixed text."): DiagnosticCheck => ({ code, label: code, level, message });
const management = (message: string) => { expect(core).toContain(message); return check("management", "fail", message); };
const disconnected = [
  check("local_backend", "pass"),
  check("local_tunnel", "warning", "This device is disconnected. Connect to run current tunnel and server checks."),
  check("local_identity", "pass"),
  check("management", "warning", "Connect this device to the selected server to check authenticated management, current server DNS, VPS networking and traffic leaks. Local checks are available while disconnected."),
];
const degraded = disconnected.map((item) => item.code === "local_tunnel" ? check("local_tunnel", "fail") : item);
const connected = [check("local_tunnel", "pass"), check("local_identity", "pass"), check("management", "pass"), check("dns", "pass"), check("server_process", "pass")];
const owner = { role: "owner" as const, endpoint: { host: "vpn.example.com", wireguard_port: 51820 } };
const member = { ...owner, role: "member" as const };
const run = (checks: DiagnosticCheck[], overrides: Partial<Parameters<typeof troubleshootSteps>[0]> = {}) =>
  troubleshootSteps({ report: { api_version: "v1", checks }, online: true, profile: owner, transport: "automatic", rotationPending: false, ...overrides });
const summary = (steps: ReturnType<typeof run>) => Object.fromEntries(steps.map((step) => [step.id, [step.status, step.message.split(".").at(-1), step.fix ?? null]]));

describe("Troubleshooting steps", () => {
  it("walks every cause in order and leaves unproven ones to check", () => {
    const steps = run(disconnected);
    expect(steps.map((step) => step.id)).toEqual(["network", "dns", "reachability", "transport", "clock", "enrollment", "membership", "service"]);
    expect(summary(steps)).toEqual({
      network: ["check", "check", null],
      dns: ["check", "check", null],
      reachability: ["check", "check", "endpointUpdate"],
      transport: ["check", "owner", "repairServer"],
      clock: ["check", "check", null],
      enrollment: ["check", "check", "restoreDevice"],
      membership: ["ok", "owner", null],
      service: ["check", "check", "repairServer"],
    });
    expect(firstTroubleshootStep(steps)).toBe(0);
  });

  it("opens at the first likely cause", () => {
    expect(summary(run(disconnected, { online: false })).network).toEqual(["problem", "offline", null]);
    const fixed = run(degraded, { transport: "direct_udp" });
    expect(summary(fixed).transport).toEqual(["problem", "fixed", "connectionSettings"]);
    expect(summary(fixed).reachability).toEqual(["check", "check", "endpointUpdate"]);
    expect(firstTroubleshootStep(fixed)).toBe(3);
    const automatic = run(degraded);
    expect(summary(automatic).reachability).toEqual(["problem", "check", "endpointUpdate"]);
    expect(firstTroubleshootStep(automatic)).toBe(2);
  });

  it("names the cause a failed management check reports", () => {
    expect(summary(run([management("The private TLS handshake failed. Check the pinned server identity, this device's enrollment and both device and VPS clocks. Do not bypass certificate verification.")])).clock)
      .toEqual(["problem", "problem", null]);
    expect(summary(run([management("The VPS rejected device authentication. Check the enrolled device certificate and recover or enroll again if it was replaced.")])).enrollment)
      .toEqual(["problem", "problem", "restoreDevice"]);
    expect(summary(run([management("The VPS rejected this device's current access. The owner can check device revocation, member suspension, expiration and access schedules.")], { profile: member })).membership)
      .toEqual(["problem", "problem", null]);
    expect(summary(run([check("local_tunnel", "pass"), management("The private management request timed out. Check the local tunnel, included management route and VPS service. A timeout alone does not identify a certificate problem.")])).service)
      .toEqual(["problem", "problem", "repairServer"]);
    expect(summary(run([check("local_identity", "fail")])).enrollment).toEqual(["problem", "problem", "restoreDevice"]);
    expect(summary(run(disconnected, { rotationPending: true })).enrollment).toEqual(["problem", "rotation", "keyRotation"]);
  });

  it("clears every cause an authenticated connection rules out", () => {
    const steps = run(connected);
    expect(steps.every((step) => step.status === "ok")).toBe(true);
    expect(firstTroubleshootStep(steps)).toBe(0);
    expect(summary(run([...connected, check("dns", "fail")])).dns).toEqual(["problem", "vps", "repairServer"]);
    expect(summary(run([...connected, check("wireguard", "fail")])).service).toEqual(["problem", "problem", "repairServer"]);
  });

  it("ignores checks that could not run", () => {
    const unavailable = [check("dns_resolver_response", "warning", "A current DNS response check is unavailable. Try again after other diagnostics finish."), check("external_reachability", "warning")];
    expect(summary(run([...disconnected, ...unavailable])).dns).toEqual(["check", "check", null]);
    expect(run([...disconnected, ...unavailable]).some((step) => step.status === "problem")).toBe(false);
  });

  it("offers fixes only to devices that can use them", () => {
    const steps = summary(run([...connected, check("dns", "fail"), check("server_process", "fail")], { profile: member }));
    expect(steps.dns).toEqual(["problem", "vps", null]);
    expect(steps.service).toEqual(["problem", "problem", null]);
    expect(summary(run(disconnected, { profile: member })).transport).toEqual(["check", "member", null]);
    expect(summary(run(disconnected, { profile: member })).membership).toEqual(["check", "check", null]);
  });

  it("follows the server’s address and HTTPS setup", () => {
    expect(summary(run(disconnected, { profile: { ...owner, endpoint: { host: "203.0.113.7", wireguard_port: 51820 } } })).dns).toEqual(["ok", "address", null]);
    expect(summary(run(disconnected, { profile: { ...owner, endpoint: { host: "2001:db8::7", wireguard_port: 51820 } } })).dns).toEqual(["ok", "address", null]);
    const cdn = { ...owner, tls_like: { port: 443, server_public_key: "key", certificate_sha256: "pin", https: { server_name: "vpn.example.com", path: "/", cdn: true } } };
    expect(summary(run(disconnected, { profile: cdn })).transport).toEqual(["check", "automatic", null]);
  });
});
