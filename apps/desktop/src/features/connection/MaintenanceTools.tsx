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
} from "@phosphor-icons/react";
import { canRotateDeviceKeys } from "../../access";
import type { ServerWorkspaceModel } from "./useServerWorkspace";
import { RecoveryKeys } from "../settings/RecoveryKeys";

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
  const blockedRotation = rotationPending
    ? "Resume device key rotation first."
    : undefined;
  const deviceActions = [
    {
      label: "Export device backup",
      description:
        blockedRotation ??
        "Encrypt this device's VPN and management identity locally.",
      icon: DownloadSimple,
      disabled: rotationPending,
      run: () => model.setBackupOpen(true),
    },
    {
      label: "Restore device backup",
      description: "Import an encrypted identity from a local backup file.",
      icon: UploadSimple,
      disabled: false,
      run: onRestoreDevice,
    },
    {
      label: rotationPending ? "Resume key rotation" : "Rotate device keys",
      description: rotationPending
        ? "Finish this device's interrupted rotation."
        : connected
          ? "Replace only this device's VPN and management keys."
          : "Connect to this server to rotate its device keys.",
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
            label: "Back up VPS",
            description:
              blockedRotation ??
              "Encrypt the server configuration and authorization state.",
            icon: HardDrives,
            disabled: false,
            run: () => model.setMaintenanceReview("backup"),
          },
          {
            label: "Restore or migrate VPS",
            description:
              blockedRotation ?? "Restore server state on a verified host.",
            icon: UploadSimple,
            disabled: false,
            run: () => model.setMaintenanceReview("restore"),
          },
        ]
      : [];
  const maintenance = [
    {
      label:
        profile.role === "owner"
          ? "Move devices to a new VPS address"
          : "Apply server address update",
      description:
        blockedRotation ??
        (anotherConnected
          ? "Disconnect the other server first."
          : "Review a signed address update and move devices to the new endpoint."),
      icon: GlobeHemisphereWest,
      disabled: !localKnown || rotationPending || anotherConnected,
      run: () => model.setEndpointUpdateOpen(true),
    },
    ...(profile.role === "owner"
      ? [
          {
            label: "Update VPS software",
            description:
              "Update SirinVPN on this VPS. Review the operation before proceeding.",
            icon: ArrowClockwise,
            disabled: false,
            run: () => {
              model.setMaintenanceReview("update");
            },
          },
          {
            label: "Repair VPS configuration",
            description:
              "Restore networking and service configuration. Review the repair plan.",
            icon: Wrench,
            disabled: false,
            run: () => {
              model.setMaintenanceReview("repair");
            },
          },
        ]
      : []),
    {
      label: "Remove saved server or uninstall SirinVPN",
      description:
        blockedRotation ??
        "Choose local removal or server software uninstall. Your rented VPS is preserved.",
      icon: Trash,
      disabled: rotationPending || !localKnown,
      run: () => model.setRemoveOpen(true),
    },
  ];
  const sections =
    category === "recovery"
      ? [
          { title: "This device · identity & backup", actions: deviceActions },
          ...(serverRecovery.length
            ? [{ title: "VPS · backup & recovery", actions: serverRecovery }]
            : []),
        ]
      : [{ title: `${profile.name} · maintenance`, actions: maintenance }];
  return (
    <div className="settings-sections">
      {category === "recovery" && model.accessLevel !== "member" && <RecoveryKeys key={profile.id} profile={profile} connected={connected} owner={model.accessLevel === "owner"} />}
      {sections.map((section) => (
        <section
          key={section.title}
          className="settings-card maintenance-tools"
        >
          <h2>{section.title}</h2>
          <div className="settings-action-list">
            {section.actions.map(
              ({ label, description, icon: Icon, disabled, run }) => (
                <button
                  key={label}
                  className={`settings-action ${label.startsWith("Remove") ? "danger" : ""}`}
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
              ),
            )}
          </div>
        </section>
      ))}
    </div>
  );
}
