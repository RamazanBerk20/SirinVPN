import { DialogContent } from "../../components/DialogContent";
import { DiagnosticResults } from "../../components/DiagnosticResults";
import { useEffect } from "react";
import { MaintenanceReview } from "./MaintenanceReview";
import type { Page } from "../../components/Navigation";
import * as Dialog from "@radix-ui/react-dialog";
import { ArrowClockwise } from "@phosphor-icons/react";
import { EndpointUpdateDialog } from "../settings/EndpointUpdateDialog";
import { KeyRotationDialog } from "../settings/KeyRotationDialog";
import { RepairServerDialog } from "../settings/RepairServerDialog";
import { VpsUpdateDialog } from "../settings/VpsUpdateDialog";
import { VpsBackupDialog } from "../settings/VpsBackupDialog";
import { VpsRestoreDialog } from "../settings/VpsRestoreDialog";
import { ExportBackupDialog } from "../settings/ExportBackupDialog";
import { RemoveServerDialog } from "../settings/RemoveServerDialog";

import type { ServerWorkspaceModel } from "./useServerWorkspace";

export function WorkspaceDialogs({
  model,
  view,
  onReturnHome,
  onReviewAccess,
}: {
  model: ServerWorkspaceModel;
  view: Page;
  onReturnHome?: () => void;
  onReviewAccess?: () => void;
}) {
  const {
    diagnostics,
    diagnosticsOpen,
    setDiagnosticsOpen,
    backupOpen,
    setBackupOpen,
    vpsBackupOpen,
    setVpsBackupOpen,
    vpsRestoreOpen,
    setVpsRestoreOpen,
    repairOpen,
    setRepairOpen,
    rotationOpen,
    setRotationOpen,
    endpointUpdateOpen,
    setEndpointUpdateOpen,
    rotationPending,
    removeOpen,
    setRemoveOpen,
    connected,
    refreshRotationPending,
    profile,
    localStatus,
    onAccessChanged,
    onRemoved,
  } = model;
  useEffect(() => { setDiagnosticsOpen(false); }, [view, profile.id, setDiagnosticsOpen]);
  return (
    <>
      <MaintenanceReview model={model} />
      <Dialog.Root open={diagnosticsOpen} onOpenChange={setDiagnosticsOpen}>
        <Dialog.Portal>
          <Dialog.Overlay className="dialog-overlay" />
          <DialogContent className="dialog-content diagnostics-dialog" heading="Current diagnostics"
            description="Checks describe current device and server conditions. Results are discarded when this view closes; copying keeps the sanitized text in your clipboard.">
            {!diagnostics ? (
              <div className="diagnostic-loading">
                <ArrowClockwise className="spin" /> Checking current device and server conditions
              </div>
            ) : (
              <DiagnosticResults report={diagnostics} />
            )}
          </DialogContent>
        </Dialog.Portal>
      </Dialog.Root>
      <ExportBackupDialog
        profile={profile}
        open={backupOpen}
        onOpenChange={setBackupOpen}
      />
      <VpsBackupDialog
        profile={profile}
        open={vpsBackupOpen}
        onOpenChange={setVpsBackupOpen}
        disconnected={localStatus.state === "disconnected"}
      />
      <VpsRestoreDialog
        profile={profile}
        onReviewAccess={onReviewAccess}
        onMoveDevices={() => setEndpointUpdateOpen(true)}
        open={vpsRestoreOpen}
        onOpenChange={setVpsRestoreOpen}
        disconnected={localStatus.state === "disconnected"}
        onCompleted={onAccessChanged}
      />
      <VpsUpdateDialog
        profile={profile}
        open={repairOpen && model.repairIntent === "update"}
        onOpenChange={setRepairOpen}
        disconnected={localStatus.state === "disconnected" && !localStatus.kill_switch_enabled && !localStatus.auto_reconnect_enabled}
        onCompleted={onAccessChanged}
      />
      <RepairServerDialog
        intent={model.repairIntent === "dns" ? "dns" : "repair"}
        profile={profile}
        open={repairOpen && model.repairIntent !== "update"}
        onOpenChange={setRepairOpen}
        disconnected={localStatus.state === "disconnected"}
        onCompleted={onAccessChanged}
        onReturnHome={onReturnHome}
      />
      <KeyRotationDialog
        profile={profile}
        open={rotationOpen}
        onOpenChange={setRotationOpen}
        pending={rotationPending}
        onCompleted={async () => {
          await onAccessChanged();
          await refreshRotationPending();
        }}
        onPendingChanged={refreshRotationPending}
      />
      <EndpointUpdateDialog
        profile={profile}
        open={endpointUpdateOpen}
        onOpenChange={setEndpointUpdateOpen}
        connected={connected}
        onCompleted={onAccessChanged}
      />
      <RemoveServerDialog
        profile={profile}
        open={removeOpen}
        onOpenChange={setRemoveOpen}
        onRemoved={onRemoved}
      />
    </>
  );
}
