import { useEffect, useState } from "react";
import { api } from "../../api";
import { InlineError } from "../../components/ui";
import { errorMessage } from "../../lib/errors";
import type { ReleaseUpdateStatus } from "../../types";
import { t } from "../../i18n";

export function ReleaseRecovery({ busy, setBusy }: { busy: boolean; setBusy: (value: boolean) => void }) {
  const [status, setStatus] = useState<ReleaseUpdateStatus | null>(null);
  const [confirmed, setConfirmed] = useState(false);
  const [done, setDone] = useState(false);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    let active = true;
    void api.releaseUpdateStatus().then((next) => { if (active) setStatus(next); })
      .catch((reason) => { if (active) setError(errorMessage(reason, t("release.recovery.errorStatus"))); });
    return () => { active = false; };
  }, []);
  const rollback = async () => {
    if (!confirmed || !status?.rollback_version || busy) return;
    setBusy(true);
    setError(null);
    try { await api.rollbackReleaseUpdate(status.rollback_version); setDone(true); }
    catch (reason) { setError(errorMessage(reason, t("release.recovery.errorRestore"))); }
    finally { setConfirmed(false); setBusy(false); }
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
      {done ? <p>{t("release.recovery.restored", { version: status.rollback_version })}</p> : <>
        <label className="replacement-option">
          <input type="checkbox" checked={confirmed} disabled={busy} onChange={(event) => setConfirmed(event.target.checked)} />
          <span><strong>{t("release.recovery.restoreConfirm", { version: status.rollback_version })}</strong><small>{t("release.recovery.restoreNote")}</small></span>
        </label>
        <button className="secondary-button" type="button" disabled={!confirmed || busy} onClick={() => void rollback()}>{t("release.recovery.restore")}</button>
      </>}
    </div>}
    {error && <InlineError message={error} />}
  </>;
}
