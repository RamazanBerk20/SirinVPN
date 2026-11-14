import { afterEach, expect, it } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { createElement } from "react";
import { appError } from "../../lib/errors";
import { pseudoLocales, setLocale, sourceLocale, t } from "../../i18n";
import { describeInstallFailure, InstallFailure } from "./SetupOutcome";

afterEach(() => { cleanup(); setLocale(sourceLocale); });
const coded = (code: string, params: Record<string, string> = {}) => Object.assign(new Error("Backend text."), { code, params });
const describe = (code: string, params?: Record<string, string>) => describeInstallFailure(appError(coded(code, params)));

it("reads the failed phase and whether the server was changed from the error code", () => {
  expect(describe("install_phase_failed", { phase: "connection" })).toEqual({ stage: "connect", change: "unchanged" });
  expect(describe("install_phase_failed", { phase: "artifact upload" })).toEqual({ stage: "upload", change: "unchanged" });
  expect(describe("install_phase_failed", { phase: "owner enrollment" })).toEqual({ stage: "configure", change: "rolledBack" });
  expect(describe("install_incompatible")).toEqual({ stage: "check", change: "unchanged" });
  expect(describe("install_input_rejected")).toEqual({ stage: null, change: "unchanged" });
  expect(describe("install_ssh_failed")).toEqual({ stage: "connect", change: "unchanged" });
  expect(describe("install_rolled_back")).toEqual({ stage: null, change: "rolledBack" });
  expect(describe("install_outcome_unknown", { host: "203.0.113.1", reason: "timeout" })).toEqual({ stage: null, change: "unknown" });
  expect(describeInstallFailure(appError(new Error("Server setup was interrupted.")))).toEqual({ stage: null, change: "unknown" });
  expect(describeInstallFailure({ code: "install_phase_failed", params: { phase: "commit" }, detail: "" })).toEqual({ stage: "configure", change: "rolledBack" });
  expect(describeInstallFailure({ code: "install_phase_failed", params: { phase: "something new" }, detail: "" })).toEqual({ stage: null, change: "unknown" });
});

it("still says what changed on the server in another locale (it used to parse the localized text)", () => {
  setLocale(pseudoLocales.expanded);
  const error = appError(Object.assign(new Error("server transaction failed during server configuration: apt-get exited with status 100"), { code: "install_phase_failed", params: { phase: "server configuration" } }));
  render(createElement(InstallFailure, { error, fallback: t("onboarding.setup.error.install"), fingerprint: "SHA256:x", steps: false, canRetry: true, onRetry: () => {}, onBack: () => {} }));
  expect(screen.getByText(t("onboarding.setup.failed.change.rolledBack"))).toBeTruthy();
  // The installer's English words are there, behind "Technical details".
  expect(screen.getByRole("alert").textContent).not.toContain("100");
  fireEvent.click(screen.getByRole("button", { name: t("common.error.technicalDetails") }));
  expect(screen.getByRole("alert").textContent).toContain("100");
});

it("says a rejected input changed nothing on the server, in the interface language", () => {
  setLocale(pseudoLocales.expanded);
  const error = appError(Object.assign(new Error("invalid installation input: server artifact is empty or exceeds 64 MiB"), { code: "install_input_rejected", params: {} }));
  render(createElement(InstallFailure, { error, fallback: t("onboarding.setup.error.install"), fingerprint: "SHA256:x", steps: false, canRetry: true, onRetry: () => {}, onBack: () => {} }));
  expect(screen.getByText(t("onboarding.setup.failed.change.unchanged"))).toBeTruthy();
  expect(screen.queryByText(t("onboarding.setup.failed.change.unknown"))).toBeNull();
  expect(screen.getByRole("alert").textContent).toContain(t("common.errorCode.install_input_rejected"));
  expect(screen.getByRole("alert").textContent).not.toContain("64 MiB");
});
