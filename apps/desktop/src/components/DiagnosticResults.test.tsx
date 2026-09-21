import { afterEach, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { DiagnosticResults } from "./DiagnosticResults";

afterEach(() => { cleanup(); vi.unstubAllGlobals(); });

it("copies only the displayed report after an explicit click", async () => {
  const writeText = vi.fn().mockResolvedValue(undefined);
  vi.stubGlobal("navigator", { clipboard: { writeText } });
  const report = { api_version: "v1", checks: [{ code: "local_tunnel", label: "Selected VPN connection", level: "warning" as const, message: "This device is disconnected." }],
    unrelated_identity: "never-export-this-field" };
  render(<DiagnosticResults report={report} />);
  expect(writeText).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole("button", { name: "Copy sanitized report" }));
  await waitFor(() => expect(writeText).toHaveBeenCalledTimes(1));
  const text = writeText.mock.calls[0][0];
  expect(text).toContain("This device is disconnected.");
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
  expect(Array.from(container.querySelectorAll(".diagnostic-row strong")).map((item) => item.textContent)).toEqual([
    "IPv4 NAT", "Public reachability", "Compatibility", "Traffic protection", "Configured routing", "DNS response",
  ]);
  expect(container.querySelector("details")?.open).toBe(false);
  expect(screen.getAllByText("Not checked").length).toBe(2);
  expect(screen.getByText("Service reported")).toBeTruthy();
  expect(screen.getAllByText("Configuration inspected").length).toBe(2);
  expect(screen.getByText("Observed test result")).toBeTruthy();
  fireEvent.click(screen.getByRole("button", { name: "Copy sanitized report" }));
  await waitFor(() => expect(writeText).toHaveBeenCalledOnce());
  const copied = writeText.mock.calls[0][0];
  expect(copied.indexOf("IPv4 NAT")).toBeLessThan(copied.indexOf("Public reachability"));
  expect(copied.indexOf("Public reachability")).toBeLessThan(copied.indexOf("Traffic protection"));
  expect(copied).toContain("Evidence: Service reported");
});
