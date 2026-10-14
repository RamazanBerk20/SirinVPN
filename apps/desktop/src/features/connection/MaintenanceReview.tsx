import { useEffect, useState } from "react";
import * as Dialog from "@radix-ui/react-dialog";
import { DialogContent } from "../../components/DialogContent";
import { InlineError } from "../../components/ui";
import { api } from "../../api";
import { errorMessage } from "../../lib/errors";
import { t, type MessageKey } from "../../i18n";
import type { ServerWorkspaceModel } from "./useServerWorkspace";

const plans = {
  backup: {
    title: "maintenance.operation.backup.title",
    steps: [
      "maintenance.operation.backup.steps.read",
      "maintenance.operation.backup.steps.encrypt",
    ],
  },
  restore: {
    title: "maintenance.operation.restore.title",
    steps: [
      "maintenance.operation.restore.steps.choose",
      "maintenance.operation.restore.steps.review",
      "maintenance.operation.interruption",
    ],
  },
  update: {
    title: "maintenance.operation.update.title",
    steps: [
      "maintenance.operation.update.steps.review",
      "maintenance.operation.update.steps.rollback",
      "maintenance.operation.interruption",
    ],
  },
  repair: {
    title: "maintenance.operation.repair.title",
    steps: [
      "maintenance.operation.repair.steps.reapply",
      "maintenance.operation.repair.steps.preserve",
      "maintenance.operation.interruption",
    ],
  },
  dns: {
    title: "maintenance.operation.dns.title",
    steps: [
      "maintenance.operation.dns.steps.choose",
      "maintenance.operation.dns.steps.apply",
      "maintenance.operation.interruption",
    ],
  },
} as const satisfies Record<string, { title: MessageKey; steps: readonly MessageKey[] }>;
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
        errorMessage(reason, t("maintenance.review.disconnectFailed")),
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
          heading={<>{plan && t(plan.title)}</>}
          description={t("maintenance.review.description", { name: model.profile.name })}
          closeDisabled={busy} closeLabel={t("maintenance.review.close")}>
          <ol className="maintenance-plan">
            {plan?.steps.map((step) => (
              <li key={step}>{t(step)}</li>
            ))}
          </ol>
          {model.rotationPending && (
            <div className="maintenance-prerequisite">
              <p>{t("maintenance.review.rotationFirst")}</p>
              <button
                className="secondary-button"
                onClick={() => {
                  model.setMaintenanceReview(null);
                  model.setRotationOpen(true);
                }}
              >
                {t("maintenance.review.reviewRotation")}
              </button>
            </div>
          )}
          {!disconnected && (
            <div className="maintenance-prerequisite">
              <p>
                {!model.localKnown
                  ? t("maintenance.review.refreshFirst")
                  : local.kill_switch_enabled
                    ? t("maintenance.review.disconnectFirstKillSwitch")
                    : t("maintenance.review.disconnectFirst")}
              </p>
              <button
                className="secondary-button"
                disabled={busy}
                onClick={() =>
                  void (model.localKnown ? disconnect() : model.onRefresh())
                }
              >
                {busy
                  ? t("maintenance.review.disconnecting")
                  : model.localKnown
                    ? t("maintenance.review.disconnect")
                    : t("maintenance.review.refresh")}
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
              {t("common.action.continue")}
            </button>
          </div>
        </DialogContent>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
