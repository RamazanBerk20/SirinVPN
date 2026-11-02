import { SecretInput, SecretTextarea } from "../../components/SecretInput";
import { ConfirmationRow } from "../../components/ConfirmationRow";
import { useEffect, useRef, useState } from "react";
import { open } from "../../lib/nativeDialog";
import { FileArrowUp, Lifebuoy, UploadSimple, Warning } from "@phosphor-icons/react";
import { api } from "../../api";
import { Field, InlineError } from "../../components/ui";
import { HashValue } from "../../components/CopyValue";
import { notify } from "../../components/Toasts";
import { errorMessage } from "../../lib/errors";
import type { RecoveryPreview, ServerProfile } from "../../types";
import { t } from "../../i18n";
import { fileName } from "./ImportBackupFlow";
import type { SetupNext } from "./SetupFlow";

type Busy = "" | "preview" | "recover" | "file";
const busyLabels = { preview: "onboarding.recover.reviewing", recover: "onboarding.recover.submitting", file: "onboarding.recover.file.opening" } as const;

export function RecoverAccessFlow({ onComplete, compact = false }: { onComplete: (profile: ServerProfile, next?: SetupNext) => Promise<void>; compact?: boolean }) {
  const [key, setKey] = useState(""), [password, setPassword] = useState(""), [deviceName, setDeviceName] = useState(() => t("onboarding.recover.defaultDeviceName"));
  const [file, setFile] = useState("");
  const [preview, setPreview] = useState<RecoveryPreview | null>(null);
  const [confirmed, setConfirmed] = useState(false), [replace, setReplace] = useState(false);
  const [busy, setBusy] = useState<Busy>(""), [error, setError] = useState<string | null>(null), [fileError, setFileError] = useState("");
  // Recovery needs the VPN off; say so only while a tunnel is up.
  const [tunnelUp, setTunnelUp] = useState(false);
  const revision = useRef(0), inFlight = useRef(false);
  useEffect(() => () => { revision.current += 1; }, []);
  useEffect(() => {
    let live = true;
    api.localStatus().then((status) => { if (live) setTunnelUp(status.state !== "disconnected"); }).catch(() => undefined);
    return () => { live = false; };
  }, []);
  const reset = (value: string) => { revision.current += 1; setKey(value); setPreview(null); setConfirmed(false); setReplace(false); };
  const action = async (kind: Exclude<Busy, "">, work: () => Promise<void>, fallback = t("onboarding.recover.error"), report: (message: string) => void = setError) => {
    if (inFlight.current) return;
    inFlight.current = true;
    setBusy(kind); setError(null); setFileError("");
    try { await work(); } catch (reason) { report(errorMessage(reason, fallback)); }
    finally { inFlight.current = false; setBusy(""); }
  };
  // The file comes first; its password is asked for once there is a file to open.
  const chooseFile = () => void action("file", async () => {
    const path = await open({ multiple: false, filters: [{ name: t("onboarding.recover.file.type"), extensions: ["sirrec"] }] });
    if (typeof path === "string") { setFile(path); setPassword(""); }
  }, t("onboarding.recover.file.pickerError"), setFileError);
  const openFile = () => void action("file", async () => {
    reset((await api.importRecoveryPackage(file, password)).key);
    setPassword(""); setFile("");
    notify(t("onboarding.recover.file.loaded"));
  }, t("onboarding.recover.file.openError"), setFileError);
  return <form className={`setup-form join-form ${compact ? "compact" : ""}`} onSubmit={(event) => {
    event.preventDefault(); void action(preview ? "recover" : "preview", async () => {
      if (!key.trim()) return;
      if (!preview) {
        const current = revision.current;
        const next = await api.previewRecoveryKey(key.trim());
        if (revision.current === current) setPreview(next);
        return;
      }
      if (!confirmed || !deviceName.trim() || (preview.existing_profile && !replace)) return;
      const profile = await api.recoverOwnerAccess(key.trim(), deviceName.trim(), confirmed, replace);
      setKey(""); setPassword(""); setPreview(null);
      // Recovery used up the old key: go straight to Keys & recovery to make a new one.
      notify(t("onboarding.recover.done", { name: profile.name }), "info");
      await onComplete(profile, "recovery");
    });
  }}>
    <div className="form-heading"><span><Lifebuoy size={20} /></span><div><h2>{t("onboarding.recover.title")}</h2><p>{t("onboarding.recover.summary")}</p></div></div>
    {tunnelUp && <p className="warning-note" role="status"><Warning size={18} weight="fill" /><span>{t("onboarding.recover.disconnectFirst")}</span></p>}
    <fieldset className="setup-fields" disabled={busy !== ""}>
      <Field label={t("onboarding.recover.key")} hint={t("onboarding.recover.keyHint")}><SecretTextarea aria-label={t("onboarding.recover.key")} rows={5} value={key} onChange={(event) => reset(event.target.value)} spellCheck={false} autoComplete="off" /></Field>
      <details className="recovery-file" open={file !== "" || undefined}><summary>{t("onboarding.recover.file.toggle")}</summary>
        <div className="recovery-file-content">
          <button type="button" className={`file-pick ${file ? "chosen" : ""}`} title={file || undefined} onClick={chooseFile}>
            <FileArrowUp size={22} aria-hidden="true" />
            <span><strong>{file ? fileName(file) : t("onboarding.recover.file.choose")}</strong>{file && <small>{t("onboarding.backup.change")}</small>}</span>
          </button>
          {file && <>
            <Field label={t("onboarding.recover.file.password")}><SecretInput type="password" value={password} onChange={(event) => setPassword(event.target.value)} autoComplete="current-password" /></Field>
            <button className="secondary-button" type="button" disabled={!password} onClick={openFile}><UploadSimple size={17} />{busy === "file" ? t(busyLabels.file) : t("onboarding.recover.file.open")}</button>
          </>}
          {fileError && <InlineError message={fileError} />}
        </div>
      </details>
      {preview && <>
        <div className="recovery-target"><strong>{preview.preview.server_name}</strong><p>{preview.preview.host}</p>
          <HashValue label={t("onboarding.recover.serverIdentity")} value={preview.preview.server_identity_fingerprint} />
        </div>
        <Field label={t("onboarding.recover.deviceName")}><input maxLength={64} value={deviceName} onChange={(event) => setDeviceName(event.target.value)} /></Field>
        <ConfirmationRow checked={confirmed} onChange={setConfirmed} danger>{t("onboarding.recover.confirmRevoke")}</ConfirmationRow>
        {preview.existing_profile && <label className="preference-checkbox"><input type="checkbox" checked={replace} onChange={(event) => setReplace(event.target.checked)} /><span>{t("onboarding.recover.replaceProfile", { name: preview.preview.server_name })}</span></label>}
      </>}
    </fieldset>
    {error && <InlineError message={error} />}
    <button className={`primary-button${preview ? " danger-action" : ""}`} type="submit" disabled={busy !== "" || !key.trim() || Boolean(preview && (!confirmed || !deviceName.trim() || (preview.existing_profile && !replace)))}>{busy === "preview" || busy === "recover" ? t(busyLabels[busy]) : preview ? t("onboarding.recover.submit") : t("onboarding.recover.review")}</button>
  </form>;
}
