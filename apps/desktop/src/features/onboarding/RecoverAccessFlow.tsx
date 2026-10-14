import { SecretInput, SecretTextarea } from "../../components/SecretInput";
import { useEffect, useRef, useState } from "react";
import { open } from "../../lib/nativeDialog";
import { Key, UploadSimple } from "@phosphor-icons/react";
import { api } from "../../api";
import { Field, InlineError } from "../../components/ui";
import { CopyValue } from "../../components/CopyValue";
import { errorMessage } from "../../lib/errors";
import type { RecoveryPreview, ServerProfile } from "../../types";
import { t } from "../../i18n";

export function RecoverAccessFlow({ onComplete, compact = false }: { onComplete: (profile: ServerProfile) => Promise<void>; compact?: boolean }) {
  const [key, setKey] = useState(""), [password, setPassword] = useState(""), [deviceName, setDeviceName] = useState(() => t("onboarding.recover.defaultDeviceName"));
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
    try { await work(); } catch (reason) { setError(errorMessage(reason, t("onboarding.recover.error"))); }
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
    <div className="form-heading"><span><Key size={20} /></span><div><h2>{t("onboarding.recover.title")}</h2><p>{t("onboarding.recover.summary")}</p></div></div>
    <Field label={t("onboarding.recover.key")} hint={t("onboarding.recover.keyHint")}><SecretTextarea aria-label={t("onboarding.recover.key")} rows={5} value={key} onChange={(event) => reset(event.target.value)} spellCheck={false} autoComplete="off" /></Field>
    <details><summary>{t("onboarding.recover.file.toggle")}</summary>
      <Field label={t("onboarding.recover.file.password")}><SecretInput type="password" value={password} onChange={(event) => setPassword(event.target.value)} autoComplete="current-password" /></Field>
      <button className="secondary-button" type="button" disabled={busy || !password} onClick={() => void action(async () => {
        const path = await open({ multiple: false, filters: [{ name: t("onboarding.recover.file.type"), extensions: ["sirrec"] }] });
        if (typeof path !== "string") return;
        reset((await api.importRecoveryPackage(path, password)).key); setPassword("");
      })}><UploadSimple size={17} />{t("onboarding.recover.file.open")}</button>
    </details>
    {preview && <>
      <div className="recovery-target"><strong>{preview.preview.server_name}</strong><p>{preview.preview.host}</p>
        <div className="result-identity"><span>{t("onboarding.recover.serverIdentity")}</span><CopyValue value={preview.preview.server_identity_fingerprint} label={t("onboarding.recover.copyServerIdentity")} shorten showCopyLabel /></div>
      </div>
      <Field label={t("onboarding.recover.deviceName")}><input maxLength={64} value={deviceName} onChange={(event) => setDeviceName(event.target.value)} /></Field>
      <label className="preference-checkbox"><input type="checkbox" checked={confirmed} onChange={(event) => setConfirmed(event.target.checked)} /><span>{t("onboarding.recover.confirmRevoke")}</span></label>
      {preview.existing_profile && <label className="preference-checkbox"><input type="checkbox" checked={replace} onChange={(event) => setReplace(event.target.checked)} /><span>{t("onboarding.recover.replaceProfile", { name: preview.preview.server_name })}</span></label>}
    </>}
    {error && <InlineError message={error} />}
    <button className="primary-button" type="submit" disabled={busy || !key.trim() || Boolean(preview && (!confirmed || !deviceName.trim() || (preview.existing_profile && !replace)))}>{busy ? t("common.state.working") : preview ? t("onboarding.recover.submit") : t("onboarding.recover.review")}</button>
  </form>;
}
