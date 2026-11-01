import { useEffect, useState } from "react";
import * as Dialog from "@radix-ui/react-dialog";
import { ArrowClockwise, Check, Info, Warning } from "@phosphor-icons/react";
import { DialogContent } from "../../components/DialogContent";
import { api } from "../../api";
import { t } from "../../i18n";
import type { DiagnosticReport } from "../../types";
import type { SettingsCategory } from "../settings/SettingsLayout";
import { firstTroubleshootStep, troubleshootSteps, type TroubleshootFix } from "./troubleshooting";
import type { ServerWorkspaceModel } from "./useServerWorkspace";

const rowClass = { problem: "fail attention", check: "warning unavailable", ok: "pass passed" };

export function Troubleshooter({ model, onOpenSettings, onRestoreDevice }: {
  model: ServerWorkspaceModel;
  onOpenSettings: (category: SettingsCategory) => void;
  onRestoreDevice: () => void;
}) {
  const { troubleshootOpen: open, setTroubleshootOpen: setOpen, profile } = model;
  const [report, setReport] = useState<DiagnosticReport | null>(null);
  const [index, setIndex] = useState<number | null>(null);
  useEffect(() => {
    if (!open) return;
    let current = true;
    setIndex(null);
    // Unavailable diagnostics leave every step to the user's own check.
    void api.diagnostics(profile.id).catch(() => ({ api_version: "v1", checks: [] }))
      .then((result) => { if (current) setReport(result); });
    // Closing discards the report, as the diagnostics dialog does.
    return () => { current = false; setReport(null); };
  }, [open, profile.id]);
  const steps = report && troubleshootSteps({
    report, online: navigator.onLine, profile,
    transport: model.preferences.saved?.transport ?? "automatic", rotationPending: model.rotationPending,
  });
  const shown = steps ? index ?? firstTroubleshootStep(steps) : 0;
  const step = steps?.[shown];
  const fixes: Record<TroubleshootFix, { label: string; run: () => void }> = {
    connectionSettings: { label: t("help.troubleshoot.connectionSettings"), run: () => onOpenSettings("connection") },
    endpointUpdate: { label: t(profile.role === "owner" ? "maintenance.tools.endpoint.ownerLabel" : "maintenance.tools.endpoint.memberLabel"), run: () => model.setEndpointUpdateOpen(true) },
    repairServer: { label: t("maintenance.operation.repair.title"), run: () => model.setMaintenanceReview("repair") },
    keyRotation: { label: t("maintenance.tools.rotateKeys.resumeLabel"), run: () => model.setRotationOpen(true) },
    restoreDevice: { label: t("maintenance.tools.restoreBackup.label"), run: onRestoreDevice },
  };
  const fix = step?.fix && fixes[step.fix];
  return (
    <Dialog.Root open={open} onOpenChange={setOpen}>
      <Dialog.Portal>
        <Dialog.Overlay className="dialog-overlay" />
        <DialogContent className="dialog-content diagnostics-dialog" heading={t("help.troubleshoot.title")} description={t("help.troubleshoot.description")}
          footer={steps && <>
            <button type="button" className="secondary-button" disabled={shown === 0} onClick={() => setIndex(shown - 1)}>{t("common.action.back")}</button>
            {shown < steps.length - 1
              ? <button type="button" className="primary-button" onClick={() => setIndex(shown + 1)}>{t("help.troubleshoot.next")}</button>
              : <Dialog.Close asChild><button type="button" className="primary-button">{t("common.action.done")}</button></Dialog.Close>}
          </>}>
          {!step ? (
            <div className="diagnostic-loading"><ArrowClockwise className="spin" /> {t("help.troubleshoot.checking")}</div>
          ) : (
            <div className="troubleshoot-step">
              <p className="settings-note">{t("common.separator.pair", { first: t("help.troubleshoot.progress", { current: shown + 1, total: steps.length }), second: t(`help.troubleshoot.status.${step.status}`) })}</p>
              <div className={`diagnostic-row ${rowClass[step.status]}`}>
                <span>{step.status === "ok" ? <Check weight="bold" /> : step.status === "check" ? <Info /> : <Warning weight="fill" />}</span>
                <div>
                  <strong>{t(`help.troubleshoot.step.${step.id}`)}</strong>
                  <p>{t(step.message)}</p>
                  {fix && <div className="settings-action-row"><button type="button" className="secondary-button" onClick={() => { setOpen(false); fix.run(); }}>{fix.label}</button></div>}
                </div>
              </div>
            </div>
          )}
        </DialogContent>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
