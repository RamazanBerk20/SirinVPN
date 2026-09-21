import { useEffect, useState } from "react";
import { api } from "../../api";
import { InlineError } from "../../components/ui";
import { errorMessage } from "../../lib/errors";
import type { ReleaseUpdateStatus } from "../../types";

export function ReleaseRecovery({ busy, setBusy }: { busy: boolean; setBusy: (value: boolean) => void }) {
  const [status, setStatus] = useState<ReleaseUpdateStatus | null>(null);
  const [confirmed, setConfirmed] = useState(false);
  const [done, setDone] = useState(false);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    let active = true;
    void api.releaseUpdateStatus().then((next) => { if (active) setStatus(next); })
      .catch((reason) => { if (active) setError(errorMessage(reason, "Update recovery state is unavailable.")); });
    return () => { active = false; };
  }, []);
  const rollback = async () => {
    if (!confirmed || !status?.rollback_version || busy) return;
    setBusy(true);
    setError(null);
    try { await api.rollbackReleaseUpdate(status.rollback_version); setDone(true); }
    catch (reason) { setError(errorMessage(reason, "The previous AppImage could not be restored.")); }
    finally { setConfirmed(false); setBusy(false); }
  };
  const cancelAndroid = async () => {
    if(busy) return;
    setBusy(true);setError(null);
    try {await api.discardReleaseUpdate();setStatus(await api.releaseUpdateStatus());}
    catch(reason) {setError(errorMessage(reason,"The pending Android installation could not be cancelled."));}
    finally {setBusy(false);}
  };
  return <>
    {status?.installer_kind==="android" && <p className="settings-note">Android requires approval to install an APK and controls downgrade availability.</p>}
    {status?.installer_kind==="android" && status.pending_version && <div className="release-recovery">
      <p>Installation of {status.pending_version} is pending. Complete Android’s approval, or cancel this attempt before checking another release.</p>
      <button type="button" className="secondary-button" disabled={busy} onClick={()=>void cancelAndroid()}>Cancel pending Android installation</button>
    </div>}
    {status?.baseline_required && <p className="settings-note">For the first update, check the signed release directory for your installed version and verify its baseline. Then check a newer release.</p>}
    {status?.installer_kind === "appimage" && status.rollback_version && <div className="release-recovery">
      {done ? <p>AppImage {status.rollback_version} restored. Close and reopen SirinVPN.</p> : <>
        <label className="replacement-option">
          <input type="checkbox" checked={confirmed} disabled={busy} onChange={(event) => setConfirmed(event.target.checked)} />
          <span><strong>Restore AppImage {status.rollback_version}</strong><small>Your current settings are kept. The retained release must still be trusted and compatible.</small></span>
        </label>
        <button className="secondary-button" type="button" disabled={!confirmed || busy} onClick={() => void rollback()}>Restore previous AppImage</button>
      </>}
    </div>}
    {error && <InlineError message={error} />}
  </>;
}
