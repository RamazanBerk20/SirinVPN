import { afterEach, describe, expect, it } from "vitest";
import { formatList, pseudoLocales, setLocale, sourceLocale, t } from "../i18n";
import type { DiagnosticCheck } from "../types";
import { appError, describeError, diagnosticCause, errorCodeText, errorMessage, splitErrorMessage } from "./errors";

afterEach(() => setLocale(sourceLocale));

it("names the failed action, then the backend cause as detail", () => {
  expect(describeError(new Error("Port 22 refused the connection."), "Couldn’t connect.")).toEqual({ summary: "Couldn’t connect.", detail: "Port 22 refused the connection." });
  expect(errorMessage(new Error("Port 22 refused the connection."), "Couldn’t connect.")).toBe("Couldn’t connect.\nPort 22 refused the connection.");
  // English backend text that starts with the summary shows it once.
  expect(errorMessage(new Error("Couldn’t connect. Port 22 refused."), "Couldn’t connect.")).toBe("Couldn’t connect.\nPort 22 refused.");
  // Advice in the fallback would repeat the cause's own advice.
  expect(errorMessage(new Error("Port 22 refused the connection."), "Couldn’t connect. Try again.")).toBe("Couldn’t connect.\nPort 22 refused the connection.");
  expect(errorMessage(new Error("server transaction failed"), "Couldn’t install SirinVPN.")).toBe("Couldn’t install SirinVPN.\nServer transaction failed");
  expect(errorMessage("", "Couldn’t connect. Try again.")).toBe("Couldn’t connect. Try again.");
  expect(errorMessage(undefined, "Couldn’t connect.")).toBe("Couldn’t connect.");
  expect(splitErrorMessage("A.\nB\nC")).toEqual({ summary: "A.", detail: "B\nC" });
});

it("says a coded error in the interface language, keeping only detail the catalog lacks", () => {
  const busy = { code: "operation_in_progress", message: "Another change is already in progress.", params: {} };
  expect(describeError(busy, "Couldn’t save.")).toEqual({ summary: t("common.error.withDetail", { summary: "Couldn’t save.", detail: t("common.errorCode.operation_in_progress") }), detail: "" });
  const phase = { code: "install_phase_failed", message: "server transaction failed during network preflight: boom", params: { phase: "network preflight" } };
  expect(describeError(phase, "Couldn’t repair.").detail).toBe("Server transaction failed during network preflight: boom");
  const blocked = { code: "maintenance_blocked", message: "x", params: { blockers: ["connected", "persistent_policy", "something_new"], messages: [] } };
  expect(errorCodeText(appError(blocked))).toBe(t("common.errorCode.maintenance_blocked", { steps: formatList([t("common.maintenanceBlocker.connected"), t("common.maintenanceBlocker.persistent_policy")]) }));
  // Android names the Hetzner server `name`.
  expect(errorCodeText(appError({ code: "hetzner_create_uncertain", message: "x", params: { name: "sirinvpn-ab12" } }))).toContain("sirinvpn-ab12");
});

it("keeps the backend's cause in other locales, as detail under translated text", () => {
  setLocale(pseudoLocales.expanded);
  const shown = describeError(new Error("Hetzner Cloud may have created server sirinvpn-ab12; check the Hetzner Cloud Console"), "Localized summary.");
  // Values are not pseudo-localized: the backend's text stays readable.
  expect(shown).toEqual({ summary: "Localized summary.", detail: "Hetzner Cloud may have created server sirinvpn-ab12; check the Hetzner Cloud Console" });
});

describe("appError", () => {
  it("reads the backend's code and keeps its text", () => {
    expect(appError({ code: "backup_wrong_password", message: "Wrong.", params: {} })).toEqual({ code: "backup_wrong_password", params: {}, detail: "Wrong." });
    expect(appError(Object.assign(new Error("Hetzner may have created it."), { code: "hetzner_create_uncertain", params: { server: "sirinvpn-0a1b2c" } })))
      .toEqual({ code: "hetzner_create_uncertain", params: { server: "sirinvpn-0a1b2c" }, detail: "Hetzner may have created it." });
    const blocked = { code: "maintenance_blocked", message: "Disconnect first. Turn off the kill switch.", params: { blockers: ["connected", "persistent_policy"], messages: ["Disconnect first.", "Turn off the kill switch."] } };
    expect(appError(blocked).params.messages).toEqual(["Disconnect first.", "Turn off the kill switch."]);
  });

  it("never reads a code from the backend's text", () => {
    expect(appError({ code: "something_new", message: "plain" }).code).toBe("unknown");
    expect(appError("The backup password is incorrect.").code).toBe("unknown");
    expect(appError(new Error("The invitation has expired.")).code).toBe("unknown");
    expect(appError(undefined)).toEqual({ code: "unknown", params: {}, detail: "" });
  });

  it("limits the codes to those a caller handles", () => {
    const expired = { code: "invitation_expired", message: "Expired." };
    expect(appError(expired).code).toBe("invitation_expired");
    expect(appError(expired, ["backup_wrong_password"]).code).toBe("unknown");
  });
});

describe("diagnosticCause", () => {
  const check = (code: string, level: DiagnosticCheck["level"], message: string) => ({ code, level, message, label: code }) as DiagnosticCheck;
  it("reads the cause the check sends, never its message", () => {
    expect(diagnosticCause({ ...check("management", "fail", "anything"), cause: "management_clock" })).toBe("management_clock");
    expect(diagnosticCause(check("management", "fail", "The private TLS handshake failed. Check the clock."))).toBeNull();
    // A cause from a newer server that this version has no text for is no cause.
    expect(diagnosticCause({ ...check("management", "fail", "anything"), cause: "something_new" as never })).toBeNull();
  });
});
