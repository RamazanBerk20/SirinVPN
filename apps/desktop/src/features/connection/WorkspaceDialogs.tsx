import { DialogContent } from "../../components/DialogContent";
import { DiagnosticProgress, DiagnosticResults, DiagnosticRunFailed } from "../../components/DiagnosticResults";
import { SpeedTest } from "../../components/SpeedTest";
import { MaintenanceReview } from "./MaintenanceReview";
import * as Dialog from "@radix-ui/react-dialog";
import { EndpointUpdateDialog } from "../settings/EndpointUpdateDialog";
import { KeyRotationDialog } from "../settings/KeyRotationDialog";
import { RepairServerDialog } from "../settings/RepairServerDialog";
import { VpsUpdateDialog } from "../settings/VpsUpdateDialog";
import { VpsBackupDialog } from "../settings/VpsBackupDialog";
import { VpsRestoreDialog } from "../settings/VpsRestoreDialog";
import { VpsBackupScheduleDialog } from "../settings/VpsBackupScheduleDialog";
import { ExportBackupDialog } from "../settings/ExportBackupDialog";
import { RemoveServerDialog } from "../settings/RemoveServerDialog";
import { t } from "../../i18n";
import type { SettingsCategory } from "../settings/SettingsLayout";

import type { ServerWorkspaceModel } from "./useServerWorkspace";

/** Checks whose advice names a settings page get a button that opens it. */
export function diagnosticFixes(open: (category: SettingsCategory) => void, turnOnUpdates?: () => void) {
  const connection = { label: t("help.troubleshoot.connectionSettings"), run: () => open("connection") };
  const network = { label: t("maintenance.diagnostics.openNetwork"), run: () => open("network") };
  return { local_protection: connection, local_transport: connection, local_mtu: connection, local_routes: network, local_ipv6: network, local_dns: network, dns_blocklist: network,
    ...(turnOnUpdates && { os_security_updates: { label: t("maintenance.diagnostics.turnOnUpdates"), run: turnOnUpdates } }) };
}

export function WorkspaceDialogs({
  model,
  onReturnHome,
  onReviewAccess,
  onOpenSettings,
}: {
  model: ServerWorkspaceModel;
  onReturnHome?: () => void;
  onReviewAccess?: () => void;
  onOpenSettings?: (category: SettingsCategory) => void;
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
    vpsBackupScheduleOpen,
    setVpsBackupScheduleOpen,
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
  return (
    <>
      <MaintenanceReview model={model} />
      <Dialog.Root open={diagnosticsOpen} onOpenChange={setDiagnosticsOpen}>
        <Dialog.Portal>
          <Dialog.Overlay className="dialog-overlay" />
          <DialogContent className="dialog-content diagnostics-dialog" heading={t("maintenance.diagnostics.title")}
            description={t("maintenance.diagnostics.description")}>
            {model.diagnosticsFailed ? (
              <DiagnosticRunFailed onRunAgain={() => void model.runDiagnostics()} />
            ) : !diagnostics ? (
              <DiagnosticProgress title={t("maintenance.diagnostics.checking")} connected={connected} />
            ) : (
              <>
                <DiagnosticResults report={diagnostics} onRunAgain={() => void model.runDiagnostics()}
                  onConnect={model.localKnown && model.localStatus.state === "disconnected" && !model.anotherConnected ? () => { setDiagnosticsOpen(false); void model.toggle(); } : undefined} fixes={onOpenSettings && diagnosticFixes((category) => { setDiagnosticsOpen(false); onOpenSettings(category); },
                    profile.role === "owner" ? () => { setDiagnosticsOpen(false); model.setMaintenanceReview("security"); } : undefined)} />
                {model.canManageAccess && <SpeedTest serverId={profile.id} />}
              </>
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
      {profile.role === "owner" && (
        <VpsBackupScheduleDialog
          profile={profile}
          open={vpsBackupScheduleOpen}
          onOpenChange={setVpsBackupScheduleOpen}
          disconnected={localStatus.state === "disconnected" && !localStatus.kill_switch_enabled && !localStatus.auto_reconnect_enabled}
        />
      )}
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
        open={model.repairIntent === "update"}
        onOpenChange={setRepairOpen}
        disconnected={localStatus.state === "disconnected" && !localStatus.kill_switch_enabled && !localStatus.auto_reconnect_enabled}
        onCompleted={onAccessChanged}
        // Replaces the update dialog with the repair dialog.
        onRepair={() => model.openRepair("repair")}
      />
      <RepairServerDialog
        intent={model.repairIntent === "update" || model.repairIntent === null ? "repair" : model.repairIntent}
        profile={profile}
        open={model.repairIntent !== null && model.repairIntent !== "update"}
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
        addsPresharedKey={model.presharedKeyMissing}
        onCompleted={async () => {
          model.setPresharedKeyMissing(false);
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
