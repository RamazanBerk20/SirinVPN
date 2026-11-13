import { describe, expect, it } from "vitest";
import { workspaceDialogReducer, type WorkspaceDialog } from "./workspaceDialog";

const report = { api_version: "v1", checks: [] };
const running: WorkspaceDialog = { kind: "diagnostics", run: { state: "running", request: 2 } };

describe("workspaceDialogReducer", () => {
  it("opens one dialog at a time", () => {
    const review = workspaceDialogReducer(null, { type: "open", dialog: { kind: "review", operation: "update" } });
    expect(review).toEqual({ kind: "review", operation: "update" });
    expect(workspaceDialogReducer(review, { type: "open", dialog: { kind: "repair", intent: "update" } })).toEqual({ kind: "repair", intent: "update" });
  });
  it("closes only the named dialog", () => {
    expect(workspaceDialogReducer({ kind: "backup" }, { type: "close", kind: "backup" })).toBeNull();
    expect(workspaceDialogReducer({ kind: "backup" }, { type: "close", kind: "remove" })).toEqual({ kind: "backup" });
    expect(workspaceDialogReducer(null, { type: "close", kind: "remove" })).toBeNull();
  });
  it("finishes only the current diagnostics run", () => {
    expect(workspaceDialogReducer(running, { type: "diagnosticsFinished", request: 2, report })).toEqual({ kind: "diagnostics", run: { state: "done", report } });
    expect(workspaceDialogReducer(running, { type: "diagnosticsFinished", request: 2, report: null })).toEqual({ kind: "diagnostics", run: { state: "failed" } });
    expect(workspaceDialogReducer(running, { type: "diagnosticsFinished", request: 1, report })).toBe(running);
    expect(workspaceDialogReducer(null, { type: "diagnosticsFinished", request: 2, report })).toBeNull();
    expect(workspaceDialogReducer({ kind: "backup" }, { type: "diagnosticsFinished", request: 2, report })).toEqual({ kind: "backup" });
    const done: WorkspaceDialog = { kind: "diagnostics", run: { state: "done", report } };
    expect(workspaceDialogReducer(done, { type: "diagnosticsFinished", request: 2, report: null })).toBe(done);
  });
  it("resets", () => {
    expect(workspaceDialogReducer({ kind: "rotation" }, { type: "reset" })).toBeNull();
  });
});
