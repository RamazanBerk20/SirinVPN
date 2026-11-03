import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, expect, it } from "vitest";
import { OperationProgress, stepsAt } from "./OperationResult";
import { DiagnosticProgress } from "./DiagnosticResults";
import { t } from "../i18n";

afterEach(cleanup);

it("marks earlier steps done, the current one running and later ones waiting", () => {
  expect(stepsAt(["Confirm", "Restore", "Refresh"], 1).map((step) => step.state)).toEqual(["done", "running", "todo"]);
  render(<OperationProgress title="Restoring" steps={stepsAt(["Confirm", "Restore", "Refresh"], 1)} />);
  const items = screen.getAllByRole("listitem");
  expect(items.map((item) => item.textContent)).toEqual([
    `Confirm${t("app.operation.step.done")}`, `Restore${t("app.operation.step.running")}`, `Refresh${t("app.operation.step.todo")}`,
  ]);
  expect(items[1].getAttribute("aria-current")).toBe("step");
});

it("lists only the checks a disconnected run can make, and says how to get the rest", () => {
  render(<DiagnosticProgress title="Checking" connected={false} />);
  expect(screen.getAllByRole("listitem")).toHaveLength(2);
  expect(screen.getByText(t("maintenance.diagnostics.progress.disconnected"))).toBeTruthy();
  cleanup();
  render(<DiagnosticProgress title="Checking" connected />);
  expect(screen.getAllByRole("listitem").map((item) => item.getAttribute("data-state"))).toEqual(["running", "running", "running", "running"]);
  expect(screen.getByText(t("maintenance.diagnostics.progress.leaks.label"))).toBeTruthy();
});
