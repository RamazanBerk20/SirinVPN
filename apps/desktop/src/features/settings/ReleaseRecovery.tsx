import { useEffect, useState } from "react";
import { api } from "../../api";
import { ConfirmationRow } from "../../components/ConfirmationRow";
import { Busy, OperationResult } from "../../components/OperationResult";
import { InlineError } from "../../components/ui";
import { errorMessage } from "../../lib/errors";
import type { ReleaseUpdateStatus } from "../../types";
import { t } from "../../i18n";

export function ReleaseRecovery({ busy, setBusy, onRestored, onRestart, restarting = false }: {
  busy: boolean; setBusy: (value: boolean) => void; onRestored?: () => void;
  /** Relaunches into the restored AppImage, as after an update. */
  onRestart?: () => void; restarting?: boolean;
}) {
  const [status, setStatus] = useState<ReleaseUpdateStatus | null>(null);
  const [confirmed, setConfirmed] = useState(false);
  const [done, setDone] = useState(false), [restoring, setRestoring] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [statusFailed, setStatusFailed] = useState(false);
  const [attempt, setAttempt] = useState(0);
  useEffect(() => {
    let active = true;
    void api.releaseUpdateStatus().then((next) => { if (active) { setStatus(next); setStatusFailed(false); setError(null); } })
      .catch((reason) => { if (active) { setStatusFailed(true); setError(errorMessage(reason, t("release.recovery.errorStatus"))); } });
    return () => { active = false; };
  }, [attempt]);
  const rollback = async () => {
    if (!confirmed || !status?.rollback_version || busy) return;
    setBusy(true); setRestoring(true);
    setError(null);
    try { await api.rollbackReleaseUpdate(status.rollback_version); setDone(true); onRestored?.(); }
    catch (reason) { setError(errorMessage(reason, t("release.recovery.errorRestore"))); }
    finally { setConfirmed(false); setBusy(false); setRestoring(false); }
  };
  const cancelAndroid = async () => {
    if(busy) return;
    setBusy(true);setError(null);
    try {await api.discardReleaseUpdate();setStatus(await api.releaseUpdateStatus());}
    catch(reason) {setError(errorMessage(reason, t("release.recovery.errorCancel")));}
    finally {setBusy(false);}
  };
  return <>
    {status?.installer_kind==="android" && <p className="settings-note">{t("release.recovery.androidNote")}</p>}
    {status?.installer_kind==="android" && status.pending_version && <div className="release-recovery">
      <p>{t("release.recovery.pending", { version: status.pending_version })}</p>
      <button type="button" className="secondary-button" disabled={busy} onClick={()=>void cancelAndroid()}>{t("release.recovery.cancelPending")}</button>
    </div>}
    {status?.baseline_required && <p className="settings-note">{t("release.recovery.baselineRequired")}</p>}
    {status?.installer_kind === "appimage" && status.rollback_version && <div className="release-recovery">
      {done ? <OperationResult title={t("release.recovery.restored", { version: status.rollback_version })}>
        {onRestart && <button className="primary-button" type="button" disabled={restarting} onClick={onRestart}>
          {restarting ? <Busy label={t("release.done.restarting")} /> : t("release.done.restartNow")}
        </button>}
      </OperationResult> : <>
        <ConfirmationRow checked={confirmed} disabled={busy} onChange={setConfirmed}>
          <strong>{t("release.recovery.restoreConfirm", { version: status.rollback_version })}</strong><small>{t("release.recovery.restoreNote")}</small>
        </ConfirmationRow>
        <button className="secondary-button" type="button" disabled={!confirmed || busy} onClick={() => void rollback()}>{restoring ? <Busy label={t("release.recovery.restoring")} /> : t("release.recovery.restore")}</button>
      </>}
    </div>}
    {error && <InlineError message={error} onRetry={statusFailed ? () => setAttempt((value) => value + 1) : undefined} />}
  </>;
}
