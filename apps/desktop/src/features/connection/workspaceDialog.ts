import type { DiagnosticReport } from "../../types";
import type { MaintenanceOperation } from "./MaintenanceReview";

export type RepairIntent = "repair" | "update" | "dns" | "security";
export type DiagnosticsRun = { state: "running"; request: number } | { state: "done"; report: DiagnosticReport } | { state: "failed" };

/** The one modal dialog the server workspace shows; a second open replaces the first. */
export type WorkspaceDialog =
  | null
  | { kind: "review"; operation: MaintenanceOperation }
  | { kind: "repair"; intent: RepairIntent }
  | { kind: "diagnostics"; run: DiagnosticsRun }
  | { kind: "troubleshoot" | "backup" | "vpsBackup" | "vpsRestore" | "vpsBackupSchedule" | "rotation" | "endpointUpdate" | "remove" };
export type DialogKind = NonNullable<WorkspaceDialog>["kind"];

export type DialogAction =
  | { type: "open"; dialog: NonNullable<WorkspaceDialog> }
  /** Closes only the named dialog, so a late close from a dialog already replaced is ignored. */
  | { type: "close"; kind: DialogKind }
  | { type: "diagnosticsFinished"; request: number; report: DiagnosticReport | null }
  | { type: "reset" };

export function workspaceDialogReducer(state: WorkspaceDialog, action: DialogAction): WorkspaceDialog {
  switch (action.type) {
    case "open": return action.dialog;
    case "close": return state?.kind === action.kind ? null : state;
    case "diagnosticsFinished":
      // A report for a run that was closed or restarted is dropped.
      if (state?.kind !== "diagnostics" || state.run.state !== "running" || state.run.request !== action.request) return state;
      return { kind: "diagnostics", run: action.report ? { state: "done", report: action.report } : { state: "failed" } };
    case "reset": return null;
  }
}
