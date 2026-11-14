import { afterEach, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { pseudoLocales, setLocale, sourceLocale, t } from "../i18n";
import type { DiagnosticReport } from "../types";
import { DiagnosticResults, DiagnosticRunFailed } from "./DiagnosticResults";

afterEach(() => { cleanup(); vi.unstubAllGlobals(); setLocale(sourceLocale); });

it("copies only the displayed report after an explicit click", async () => {
  const writeText = vi.fn().mockResolvedValue(undefined);
  vi.stubGlobal("navigator", { clipboard: { writeText } });
  const report = { api_version: "v1", checks: [{ code: "local_tunnel", label: "Selected VPN connection", level: "warning" as const, message: "This device is disconnected." }],
    unrelated_identity: "never-export-this-field" };
  render(<DiagnosticResults report={report} />);
  expect(writeText).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole("button", { name: t("maintenance.diagnostics.copy") }));
  await waitFor(() => expect(writeText).toHaveBeenCalledTimes(1));
  const text = writeText.mock.calls[0][0];
  expect(text).toContain("This device is disconnected.");
  // The level tag comes from the catalog, not from the backend's level value.
  expect(text).toContain(t("maintenance.diagnostics.report.check", { level: t("maintenance.diagnostics.report.level.warning"), label: "Selected VPN connection" }));
  expect(text).not.toContain("never-export-this-field");
});

it("puts issues and unavailable checks before collapsed passes and preserves evidence in copying", async () => {
  const writeText = vi.fn().mockResolvedValue(undefined);
  vi.stubGlobal("navigator", { clipboard: { writeText } });
  const report = { api_version: "v1", checks: [
    { code: "local_protection", label: "Traffic protection", level: "pass" as const, message: "The native service reports the kill switch armed for the active connection." },
    { code: "local_routes", label: "Configured routing", level: "pass" as const, message: "Full-tunnel routing is configured." },
    { code: "dns_resolver_response", label: "DNS response", level: "pass" as const, message: "Valid DNS response in 82 ms. No query history is retained." },
    { code: "external_reachability", label: "Public reachability", level: "warning" as const, message: "Local listeners cannot establish public reachability." },
    { code: "server_report_format", label: "Compatibility", level: "warning" as const, message: "Some checks could not be safely interpreted." },
    { code: "server_nat4", label: "IPv4 NAT", level: "fail" as const, message: "The NAT rule is missing." },
  ] };
  const { container } = render(<DiagnosticResults report={report} />);
  // Known checks are named from the catalog, not by the backend's English label.
  const title = (code: string) => t(`maintenance.diagnostics.checkTitle.${code}` as never);
  expect(Array.from(container.querySelectorAll(".diagnostic-row strong")).map((item) => item.textContent)).toEqual(
    ["server_nat4", "external_reachability", "server_report_format", "local_protection", "local_routes", "dns_resolver_response"].map(title));
  expect(container.querySelector("details")?.open).toBe(false);
  const evidence = (code: "configuration" | "service" | "observed" | "notChecked") =>
    Array.from(container.querySelectorAll(".diagnostic-evidence")).filter((item) => item.textContent === t(`maintenance.diagnostics.evidence.${code}`)).length;
  expect(evidence("notChecked")).toBe(2);
  expect(evidence("service")).toBe(1);
  expect(evidence("configuration")).toBe(2);
  expect(evidence("observed")).toBe(1);
  expect(screen.getByRole("status").textContent).toBe(t("maintenance.diagnostics.summary.withUnavailable", {
    attention: t("maintenance.diagnostics.summary.attention", { count: 1 }),
    review: t("maintenance.diagnostics.summary.review", { count: 1 }),
    unavailable: t("maintenance.diagnostics.summary.unavailable", { count: 1 }),
    passed: t("maintenance.diagnostics.summary.passed", { count: 3 }),
  }));
  fireEvent.click(screen.getByRole("button", { name: t("maintenance.diagnostics.copy") }));
  await waitFor(() => expect(writeText).toHaveBeenCalledOnce());
  const copied = writeText.mock.calls[0][0];
  expect(copied.indexOf(title("server_nat4"))).toBeLessThan(copied.indexOf(title("external_reachability")));
  expect(copied.indexOf(title("external_reachability"))).toBeLessThan(copied.indexOf(title("local_protection")));
  expect(copied).toContain(t("maintenance.diagnostics.report.evidence", { evidence: t("maintenance.diagnostics.evidence.service") }));
});

it("shows leak test results as tested and not applicable families as not checked", () => {
  const report = { api_version: "v1", checks: [
    { code: "leak_ipv4", label: "IPv4 leak test", level: "pass" as const, message: "A request to an internet IPv4 address went through the VPN." },
    { code: "leak_ipv6", label: "IPv6 leak test", level: "not_applicable" as const, message: "This VPN doesn't carry IPv6, and this device has no IPv6 internet route." },
    { code: "leak_dns", label: "DNS leak test", level: "fail" as const, message: "A one-off name wasn't answered by your VPS resolver." },
  ] };
  const { container } = render(<DiagnosticResults report={report} />);
  const row = (label: string) => Array.from(container.querySelectorAll(".diagnostic-row")).find((item) => item.querySelector("strong")?.textContent === label)!;
  expect(row("DNS leak test").className).toContain("attention");
  expect(row("DNS leak test").querySelector(".diagnostic-evidence")?.textContent).toBe(t("maintenance.diagnostics.evidence.observed"));
  expect(row("IPv6 leak test").className).toContain("unavailable");
  expect(row("IPv6 leak test").querySelector(".diagnostic-evidence")?.textContent).toBe(t("maintenance.diagnostics.evidence.notApplicable"));
  expect(row("IPv4 leak test").closest("details")).not.toBeNull();
  expect(row("IPv4 leak test").querySelector(".diagnostic-evidence")?.textContent).toBe(t("maintenance.diagnostics.evidence.observed"));
});

it("shows a failed or empty run as such, with Run again, and headlines an all-pass report", () => {
  const onRunAgain = vi.fn();
  const view = render(<DiagnosticRunFailed onRunAgain={onRunAgain} />);
  expect(screen.getByRole("alert").textContent).toContain(t("maintenance.workspace.error.diagnostics"));
  expect(screen.queryByRole("status")).toBeNull();
  fireEvent.click(screen.getByRole("button", { name: t("settings.diagnostics.runAgain") }));
  expect(onRunAgain).toHaveBeenCalledOnce();
  view.rerender(<DiagnosticResults report={{ api_version: "v1", checks: [] }} />);
  expect(screen.getByText(t("settings.diagnostics.empty"))).toBeTruthy();
  view.rerender(<DiagnosticResults report={{ api_version: "v1", checks: [{ code: "local_backend", label: "Service", level: "pass" as const, message: "Running." }] }} />);
  expect(screen.getByText(t("settings.diagnostics.allPassed", { count: 1 }))).toBeTruthy();
});

it("offers a check's fix only while the check needs attention", () => {
  const run = vi.fn();
  const report = { api_version: "v1", checks: [
    { code: "local_protection", label: "Protection", level: "warning", message: "The kill switch is off." },
    { code: "local_mtu", label: "MTU", level: "pass", message: "Fine." },
  ] } as DiagnosticReport;
  render(<DiagnosticResults report={report} fixes={{ local_protection: { label: "Fix protection", run }, local_mtu: { label: "Fix MTU", run } }} />);
  fireEvent.click(screen.getByRole("button", { name: "Fix protection" }));
  expect(run).toHaveBeenCalledOnce();
  expect(screen.queryByRole("button", { name: "Fix MTU" })).toBeNull();
});

it("says each finding in the interface language from its message key, and an unknown one by its cause, the English behind Technical details", () => {
  setLocale(pseudoLocales.expanded);
  const report = { api_version: "v1", checks: [
    { code: "management", label: "VPS authentication and connectivity", level: "fail" as const, message: "The private TLS handshake failed.", cause: "management_clock" as const },
    { code: "external_reachability", label: "Provider firewall and public reachability", level: "warning" as const, message: "Local listeners cannot establish public reachability.", message_key: "external_reachability" },
    { code: "server_cpu", label: "VPS CPU", level: "warning" as const, message: "Current usage: 95%. Capacity is limited.", message_key: "resource_limited", message_params: { percent: "95" } },
    { code: "local_mtu", label: "Current path MTU", level: "warning" as const, message: "Automatic MTU: 1420 bytes. Path probing is pending.", message_key: "mtu_pending", message_params: { policy: "automatic", size: "1420" } },
    { code: "dns_zone_0_1", label: "VPS split DNS zone 1, upstream 2", level: "fail" as const, message: "No answer." },
    { code: "brand_new_check", label: "Brand new check", level: "fail" as const, message: "Something new." },
  ] } as DiagnosticReport;
  const { container } = render(<DiagnosticResults report={report} />);
  const rows = Array.from(container.querySelectorAll(".diagnostic-row"));
  const row = (code: string) => rows.find((element) => element.querySelector("strong")?.textContent === code)!;
  expect(rows[0].querySelector("strong")?.textContent).toBe(t("maintenance.diagnostics.checkTitle.management"));
  // No key: the cause in the interface language; the English only after "Technical details".
  expect(rows[0].textContent).toContain(t("maintenance.diagnostics.cause.management_clock"));
  expect(rows[0].textContent).not.toContain("The private TLS handshake failed.");
  fireEvent.click(rows[0].querySelector("button")!);
  expect(rows[0].querySelector(".error-detail")?.getAttribute("lang")).toBe("en");
  expect(rows[0].textContent).toContain("The private TLS handshake failed.");
  expect(container.textContent).toContain(t("maintenance.diagnostics.message.external_reachability"));
  expect(container.textContent).not.toContain("Local listeners");
  expect(container.textContent).toContain(t("maintenance.diagnostics.message.resource_limited", { percent: 95 }));
  expect(container.textContent).toContain(t("maintenance.diagnostics.sentences", { first: t("maintenance.diagnostics.mtuSize.automatic", { size: "1420" }), second: t("maintenance.diagnostics.message.mtu_pending") }));
  expect(row(t("maintenance.diagnostics.numberedCheck.dnsZoneUpstream", { zone: 1, upstream: 2 }))).toBeTruthy();
  // A check this version doesn't know keeps the backend's label, marked as English, and a sentence for its group.
  const unknown = row("Brand new check");
  expect(unknown.querySelector("strong")?.getAttribute("lang")).toBe("en");
  expect(unknown.textContent).toContain(t("maintenance.diagnostics.messageUnknown.attention"));
});

it("shows the native English text as is in English", () => {
  const { container } = render(<DiagnosticResults report={{ api_version: "v1", checks: [{ code: "brand_new_check", label: "Brand new check", level: "fail" as const, message: "Something new." }] }} />);
  expect(container.textContent).toContain("Something new.");
  expect(container.querySelector(".technical-detail")).toBeNull();
});
