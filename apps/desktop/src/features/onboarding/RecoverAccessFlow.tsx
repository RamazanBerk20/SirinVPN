import { SecretInput, SecretTextarea } from "../../components/SecretInput";
import { useEffect, useRef, useState } from "react";
import { open } from "../../lib/nativeDialog";
import { Key, UploadSimple } from "@phosphor-icons/react";
import { api } from "../../api";
import { Field, InlineError } from "../../components/ui";
import { CopyValue } from "../../components/CopyValue";
import { errorMessage } from "../../lib/errors";
import type { RecoveryPreview, ServerProfile } from "../../types";

export function RecoverAccessFlow({ onComplete, compact = false }: { onComplete: (profile: ServerProfile) => Promise<void>; compact?: boolean }) {
  const [key, setKey] = useState(""), [password, setPassword] = useState(""), [deviceName, setDeviceName] = useState("Recovered Owner device");
  const [preview, setPreview] = useState<RecoveryPreview | null>(null);
  const [confirmed, setConfirmed] = useState(false), [replace, setReplace] = useState(false);
  const [busy, setBusy] = useState(false), [error, setError] = useState<string | null>(null);
  const revision = useRef(0), inFlight = useRef(false);
  useEffect(() => () => { revision.current += 1; }, []);
  const reset = (value: string) => { revision.current += 1; setKey(value); setPreview(null); setConfirmed(false); setReplace(false); };
  const action = async (work: () => Promise<void>) => {
    if (inFlight.current) return;
    inFlight.current = true;
    setBusy(true); setError(null);
    try { await work(); } catch (reason) { setError(errorMessage(reason, "Owner recovery could not finish. Retry with the same key to retain the staged identity.")); }
    finally { inFlight.current = false; setBusy(false); }
  };
  return <form className={`setup-form join-form ${compact ? "compact" : ""}`} onSubmit={(event) => {
    event.preventDefault(); void action(async () => {
      if (!key.trim()) return;
      if (!preview) {
        const current = revision.current;
        const next = await api.previewRecoveryKey(key.trim());
        if (revision.current === current) setPreview(next);
        return;
      }
      if (!confirmed || !deviceName.trim() || (preview.existing_profile && !replace)) return;
      const profile = await api.recoverOwnerAccess(key.trim(), deviceName.trim(), confirmed, replace);
      setKey(""); setPassword(""); setPreview(null); await onComplete(profile);
    });
  }}>
    <div className="form-heading"><span><Key size={20} /></span><div><h2>Recover Owner access</h2><p>Use your offline recovery key or encrypted package. Recovery contacts the VPS without existing device credentials. Disconnect any current VPN before continuing.</p></div></div>
    <Field label="Recovery key" hint="The complete key starts with sirr1. It is checked locally before contacting the VPS."><SecretTextarea aria-label="Recovery key" rows={5} value={key} onChange={(event) => reset(event.target.value)} spellCheck={false} autoComplete="off" /></Field>
    <details><summary>Open an encrypted recovery package</summary>
      <Field label="Package password"><SecretInput type="password" value={password} onChange={(event) => setPassword(event.target.value)} autoComplete="current-password" /></Field>
      <button className="secondary-button" type="button" disabled={busy || !password} onClick={() => void action(async () => {
        const path = await open({ multiple: false, filters: [{ name: "Encrypted SirinVPN recovery package", extensions: ["sirrec"] }] });
        if (typeof path !== "string") return;
        reset((await api.importRecoveryPackage(path, password)).key); setPassword("");
      })}><UploadSimple size={17} />Open recovery package</button>
    </details>
    {preview && <>
      <div className="recovery-target"><strong>{preview.preview.server_name}</strong><p>{preview.preview.host}</p>
        <div className="result-identity"><span>Server identity fingerprint</span><CopyValue value={preview.preview.server_identity_fingerprint} label="recovery server identity fingerprint" shorten showCopyLabel /></div>
      </div>
      <Field label="New Owner device name"><input maxLength={64} value={deviceName} onChange={(event) => setDeviceName(event.target.value)} /></Field>
      <label className="preference-checkbox"><input type="checkbox" checked={confirmed} onChange={(event) => setConfirmed(event.target.checked)} /><span>Revoke all old Owner device identities and consume this recovery key. Other members keep their access. Administrator recovery permissions will be cleared.</span></label>
      {preview.existing_profile && <label className="preference-checkbox"><input type="checkbox" checked={replace} onChange={(event) => setReplace(event.target.checked)} /><span>Replace this device's saved profile for {preview.preview.server_name} with the recovered Owner identity.</span></label>}
    </>}
    {error && <InlineError message={error} />}
    <button className="primary-button" type="submit" disabled={busy || !key.trim() || Boolean(preview && (!confirmed || !deviceName.trim() || (preview.existing_profile && !replace)))}>{busy ? "Working" : preview ? "Recover Owner access" : "Review recovery key"}</button>
  </form>;
}
