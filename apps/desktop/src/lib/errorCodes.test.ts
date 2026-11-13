import { describe, expect, it } from "vitest";
import { en } from "../i18n/en";
import { checkTitle } from "../components/DiagnosticResults";
import { DIAGNOSTIC_CAUSES, ERROR_CODES, MAINTENANCE_BLOCKERS } from "./errors";

/**
 * The codes the native layers can send, read from their Rust sources, so a new code fails here
 * until it is in the TypeScript sets and has catalog text.
 */
const raw = (files: Record<string, string>) => Object.entries(files)
  // Only shipped code: drop each file's #[cfg(test)] module and tests.rs files.
  .filter(([path]) => !path.endsWith("/tests.rs"))
  .map(([path, text]) => [path, text.split("#[cfg(test)]")[0]] as const);
const desktop = raw(import.meta.glob<string>("../../src-tauri/src/**/*.rs", { query: "?raw", import: "default", eager: true }));
const android = raw(import.meta.glob<string>("../../../../crates/android-runtime/src/**/*.rs", { query: "?raw", import: "default", eager: true }));
const diagnostics = raw(import.meta.glob<string>(["../../../../crates/core/src/diagnostics.rs", "../../../../crates/core/src/diagnostics/*.rs"], { query: "?raw", import: "default", eager: true }));
const maintenance = raw(import.meta.glob<string>("../../../../crates/installer/src/owner_maintenance.rs", { query: "?raw", import: "default", eager: true }));

const all = (sources: (readonly [string, string])[], pattern: RegExp, only?: RegExp) => new Set(sources
  .filter(([path]) => !only || only.test(path))
  .flatMap(([, text]) => [...text.matchAll(pattern)].map((match) => match[1])));
const union = (...sets: Set<string>[]) => new Set(sets.flatMap((set) => [...set]));

const errorCodes = union(
  // CommandError::coded("code", …) on the desktop; rules::CommandError::new("code", …) and refused("code", …) on Android.
  all([...desktop, ...android], /(?:CommandError::(?:coded|new)|\brefused)\(\s*"([a-z_]+)"/g),
  // The typed-error mappings: code_of (desktop) and coded_error/typed_code (Android).
  all([...desktop, ...android], /Some\(\(\s*"([a-z_]+)"/g, /(command_error|rules)\.rs$/),
  all([...desktop, ...android], /=>\s*"([a-z_]+)",/g, /command_error\.rs$/),
  all([...desktop, ...android], /\.then\(\|\|\s*\(\s*"([a-z_]+)"/g, /command_error\.rs$/),
  all(android, /"code":\s*"([a-z_]+)"/g, /rules\.rs$/),
);
// check("code", …), constant tuples ("code", "Label"), match arms "code" => … and `code == "code"` in the sanitizer.
const checkCodes = union(
  all(diagnostics, /\bcheck\(\s*"([a-z0-9_]+)"/g),
  all(diagnostics, /:\s*\(&str[^=]*=\s*\("([a-z0-9_]+)"/g),
  all(diagnostics, /^\s*"([a-z0-9_]+)"(?:\s*\|\s*"[a-z0-9_]+")*\s*=>/gm, /remote\.rs$/),
  all(diagnostics, /\|\s*"([a-z0-9_]+)"(?=[\s|]*=>)/g, /remote\.rs$/),
  all(diagnostics, /code == "([a-z0-9_]+)"/g),
);
const causes = all(diagnostics, /\b(?:caused\([^;]*?|Some\()"([a-z_]+)"\)/gs);
const blockers = new Set([...maintenance.flatMap(([, text]) => {
  const body = /pub enum MaintenanceBlocker \{([^}]*)\}/.exec(text)?.[1] ?? "";
  return [...body.replace(/\/\/\/.*$/gm, "").matchAll(/([A-Z]\w*)/g)].map((match) => match[1].replace(/(?<!^)([A-Z])/g, "_$1").toLowerCase());
})]);

describe("Codes the native layers send", () => {
  it("are found in the Rust sources", () => {
    // Guards the patterns themselves: each kind is still found.
    expect([...errorCodes]).toEqual(expect.arrayContaining(["operation_in_progress", "maintenance_blocked", "install_rolled_back", "port_forward_public_port", "hetzner_provision_pending"]));
    expect([...checkCodes]).toEqual(expect.arrayContaining(["local_mtu", "leak_dns", "server_nat4", "server_cpu", "dns_probe_busy"]));
    expect([...causes]).toEqual(expect.arrayContaining(["not_measured", "management_clock"]));
    expect([...blockers]).toEqual(expect.arrayContaining(["connected", "unresolved_transaction"]));
  });

  it("each have a TypeScript code and catalog text", () => {
    const errorText = en.common.errorCode as Record<string, string>;
    const causeText = en.maintenance.diagnostics.cause as Record<string, string>;
    const blockerText = en.common.maintenanceBlocker as Record<string, string>;
    expect({
      errors: [...errorCodes].filter((code) => !(ERROR_CODES as readonly string[]).includes(code) || !errorText[code]),
      causes: [...causes].filter((cause) => !(DIAGNOSTIC_CAUSES as readonly string[]).includes(cause) || !causeText[cause]),
      blockers: [...blockers].filter((blocker) => !(MAINTENANCE_BLOCKERS as readonly string[]).includes(blocker) || !blockerText[blocker]),
      checks: [...checkCodes].filter((code) => !checkTitle(code)),
      numberedChecks: ["dns_tls_0", "dns_https_7", "dns_zone_31", "dns_zone_0_1"].filter((code) => !checkTitle(code)),
    }).toEqual({ errors: [], causes: [], blockers: [], checks: [], numberedChecks: [] });
    // And nothing in TypeScript that no native layer sends any more.
    expect(ERROR_CODES.filter((code) => !errorCodes.has(code))).toEqual([]);
    expect(DIAGNOSTIC_CAUSES.filter((cause) => !causes.has(cause))).toEqual([]);
  });
});
