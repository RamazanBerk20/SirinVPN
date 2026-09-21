import { useEffect, useState } from "react";
import * as Dialog from "@radix-ui/react-dialog";
import { DialogContent } from "../../components/DialogContent";
import { InlineError } from "../../components/ui";
import { api } from "../../api";
import { errorMessage } from "../../lib/errors";
import type { ServerWorkspaceModel } from "./useServerWorkspace";

const plans = {
  backup: {
    title: "Back up VPS",
    steps: [
      "Read the server configuration and authorization state over verified SSH.",
      "Encrypt the backup with a password you choose and save it on this device.",
    ],
  },
  restore: {
    title: "Restore or migrate VPS",
    steps: [
      "Choose an encrypted VPS backup and verify the target host over SSH.",
      "Review the destination and replacement plan before restoring. Server services may restart and interrupt other devices.",
    ],
  },
  update: {
    title: "Update VPS software",
    steps: [
      "Check your chosen HTTPS source and review the signed VPS release before installing it.",
      "Verify current-state compatibility and keep the previous authenticated release available for rollback.",
      "Installation restarts VPS services. Other devices may briefly lose their connection.",
    ],
  },
  repair: {
    title: "Repair VPS configuration",
    steps: [
      "Reapply SirinVPN networking, services, and DNS configuration. This also reinstalls the bundled server software.",
      "Preserve existing identities and authorization. Review any DNS changes before applying.",
      "Restart and verify SirinVPN services. Other devices may briefly lose their connection.",
    ],
  },
  dns: {
    title: "Configure VPS DNS",
    steps: [
      "Choose DNS upstreams or private records and verify the VPS over SSH.",
      "Apply changes using the repair workflow, which also reinstalls bundled server software and restarts services.",
      "DNS changes affect all devices using this VPS.",
    ],
  },
} as const;
export type MaintenanceOperation = keyof typeof plans;

export function MaintenanceReview({ model }: { model: ServerWorkspaceModel }) {
  const operation = model.maintenanceReview;
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    setError(null);
  }, [operation]);
  const local = model.localStatus;
  const disconnected =
    local.state === "disconnected" &&
    !local.kill_switch_enabled &&
    !local.auto_reconnect_enabled;
  const plan = operation ? plans[operation] : null;
  const disconnect = async () => {
    setBusy(true);
    setError(null);
    try {
      await api.disconnect();
    } catch (reason) {
      setError(
        errorMessage(reason, "The local tunnel could not be disconnected."),
      );
    } finally {
      await model.onRefresh();
      setBusy(false);
    }
  };
  const proceed = () => {
    if (!operation || !disconnected || model.rotationPending || busy) return;
    model.setMaintenanceReview(null);
    if (operation === "backup") model.setVpsBackupOpen(true);
    else if (operation === "restore") model.setVpsRestoreOpen(true);
    else {
      model.setRepairIntent(operation === "update" ? "update" : operation === "dns" ? "dns" : "repair");
      model.setRepairOpen(true);
    }
  };
  return (
    <Dialog.Root
      open={Boolean(operation)}
      onOpenChange={(open) => {
        if (!open && !busy) model.setMaintenanceReview(null);
      }}
    >
      <Dialog.Portal>
        <Dialog.Overlay className="dialog-overlay" />
        <DialogContent className="dialog-content maintenance-review"
          heading={<>{plan?.title}</>}
          description={<>Review maintenance requirements for {model.profile.name}.</>}
          closeDisabled={busy} closeLabel="Close maintenance review">
          <ol className="maintenance-plan">
            {plan?.steps.map((step) => (
              <li key={step}>{step}</li>
            ))}
          </ol>
          {model.rotationPending && (
            <div className="maintenance-prerequisite">
              <p>Finish this device's pending key rotation first.</p>
              <button
                className="secondary-button"
                onClick={() => {
                  model.setMaintenanceReview(null);
                  model.setRotationOpen(true);
                }}
              >
                Review key rotation
              </button>
            </div>
          )}
          {!disconnected && (
            <div className="maintenance-prerequisite">
              <p>
                {!model.localKnown
                  ? "Refresh this device's tunnel status before continuing."
                  : "Disconnect the active SirinVPN tunnel on this computer before the SSH operation. This step does not disconnect other members from the VPS."}
              </p>
              {local.kill_switch_enabled && model.localKnown && (
                <p>
                  Disconnect also releases this computer's traffic block and
                  stops automatic reconnect.
                </p>
              )}
              <button
                className="secondary-button"
                disabled={busy}
                onClick={() =>
                  void (model.localKnown ? disconnect() : model.onRefresh())
                }
              >
                {busy
                  ? "Disconnecting…"
                  : model.localKnown
                    ? "Disconnect this computer"
                    : "Refresh local status"}
              </button>
            </div>
          )}
          {error && <InlineError message={error} />}
          <div className="dialog-actions">
            <button
              className="primary-button"
              disabled={!disconnected || model.rotationPending || busy}
              onClick={proceed}
            >
              Continue to VPS setup
            </button>
          </div>
        </DialogContent>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
