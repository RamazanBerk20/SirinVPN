import {
  DownloadSimple,
  GlobeHemisphereWest,
  HardDrives,
  Key,
  Trash,
  UploadSimple,
  Wrench,
  ArrowClockwise,
  CaretRight,
  ClockCounterClockwise,
} from "@phosphor-icons/react";
import { canRotateDeviceKeys } from "../../access";
import { t } from "../../i18n";
import type { ServerWorkspaceModel } from "./useServerWorkspace";
import { RecoveryKeys } from "../settings/RecoveryKeys";
import { scheduleSummary, useVpsBackupSchedule } from "../settings/vpsBackupSchedules";

export function MaintenanceTools({
  model,
  category,
  onRestoreDevice,
}: {
  model: ServerWorkspaceModel;
  category: "recovery" | "maintenance";
  onRestoreDevice: () => void;
}) {
  const { rotationPending, connected, anotherConnected, profile, localKnown } =
    model;
  const backupSchedule = useVpsBackupSchedule(profile.id);
  const blockedRotation = rotationPending
    ? t("maintenance.tools.finishRotationFirst")
    : undefined;
  const deviceActions = [
    {
      id: "export-backup",
      label: t("maintenance.tools.exportBackup.label"),
      description:
        blockedRotation ??
        t("maintenance.tools.exportBackup.summary"),
      icon: DownloadSimple,
      disabled: rotationPending,
      run: () => model.setBackupOpen(true),
    },
    {
      id: "restore-backup",
      label: t("maintenance.tools.restoreBackup.label"),
      description: t("maintenance.tools.restoreBackup.summary"),
      icon: UploadSimple,
      disabled: false,
      run: onRestoreDevice,
    },
    {
      id: "rotate-keys",
      label: rotationPending
        ? t("maintenance.tools.rotateKeys.resumeLabel")
        : t("maintenance.tools.rotateKeys.label"),
      description: rotationPending
        ? t("maintenance.tools.rotateKeys.resumeSummary")
        : connected
          ? t("maintenance.tools.rotateKeys.summary")
          : t("maintenance.tools.rotateKeys.needsConnection"),
      icon: Key,
      disabled:
        !localKnown ||
        !canRotateDeviceKeys(connected, rotationPending, anotherConnected),
      run: () => model.setRotationOpen(true),
    },
  ];
  const serverRecovery =
    profile.role === "owner"
      ? [
          {
            id: "backup-vps",
            label: t("maintenance.operation.backup.title"),
            description:
              blockedRotation ??
              t("maintenance.operation.backup.summary"),
            icon: HardDrives,
            disabled: false,
            run: () => model.setMaintenanceReview("backup"),
          },
          {
            id: "schedule-vps-backups",
            label: t("vps.schedule.action"),
            description: blockedRotation ?? scheduleSummary(backupSchedule),
            icon: ClockCounterClockwise,
            disabled: false,
            run: () => model.setVpsBackupScheduleOpen(true),
          },
          {
            id: "restore-vps",
            label: t("maintenance.operation.restore.title"),
            description:
              blockedRotation ?? t("maintenance.operation.restore.summary"),
            icon: UploadSimple,
            disabled: false,
            run: () => model.setMaintenanceReview("restore"),
          },
        ]
      : [];
  const maintenance = [
    {
      id: "endpoint-update",
      label:
        profile.role === "owner"
          ? t("maintenance.tools.endpoint.ownerLabel")
          : t("maintenance.tools.endpoint.memberLabel"),
      description:
        blockedRotation ??
        (anotherConnected
          ? t("maintenance.tools.endpoint.otherConnected")
          : profile.role === "owner"
            ? t("maintenance.tools.endpoint.ownerSummary")
            : t("maintenance.tools.endpoint.memberSummary")),
      icon: GlobeHemisphereWest,
      disabled: !localKnown || rotationPending || anotherConnected,
      run: () => model.setEndpointUpdateOpen(true),
    },
    ...(profile.role === "owner"
      ? [
          {
            id: "update-vps",
            label: t("maintenance.operation.update.title"),
            description: t("maintenance.operation.update.summary"),
            icon: ArrowClockwise,
            disabled: false,
            run: () => {
              model.setMaintenanceReview("update");
            },
          },
          {
            id: "repair-vps",
            label: t("maintenance.operation.repair.title"),
            description: t("maintenance.operation.repair.summary"),
            icon: Wrench,
            disabled: false,
            run: () => {
              model.setMaintenanceReview("repair");
            },
          },
        ]
      : []),
    {
      id: "remove",
      danger: true,
      label: t("maintenance.tools.remove.label"),
      description:
        blockedRotation ??
        t("maintenance.tools.remove.summary"),
      icon: Trash,
      disabled: rotationPending || !localKnown,
      run: () => model.setRemoveOpen(true),
    },
  ];
  const sections =
    category === "recovery"
      ? [
          { id: "device", title: t("maintenance.tools.deviceTitle"), actions: deviceActions },
          ...(serverRecovery.length
            ? [{ id: "vps", title: t("maintenance.tools.vpsTitle"), actions: serverRecovery }]
            : []),
        ]
      : [{ id: "maintenance", title: t("maintenance.tools.serverTitle", { name: profile.name }), actions: maintenance }];
  return (
    <div className="settings-sections">
      {category === "recovery" && model.accessLevel !== "member" && <RecoveryKeys key={profile.id} profile={profile} connected={connected} owner={model.accessLevel === "owner"} />}
      {sections.map((section) => (
        <section
          key={section.id}
          className="settings-card maintenance-tools"
        >
          <h2>{section.title}</h2>
          <div className="settings-action-list">
            {section.actions.map(
              (action) => {
                const { id, label, description, icon: Icon, disabled, run } = action;
                const danger = "danger" in action && action.danger;
                return (
                  <button
                    key={id}
                    className={`settings-action ${danger ? "danger" : ""}`}
                    onClick={run}
                    disabled={disabled}
                  >
                    <Icon size={22} />
                    <span>
                      <strong>{label}</strong>
                      <small>{description}</small>
                    </span>
                    <CaretRight size={17} />
                  </button>
                );
              },
            )}
          </div>
        </section>
      ))}
    </div>
  );
}
