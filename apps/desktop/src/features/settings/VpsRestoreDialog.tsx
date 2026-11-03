import { SecretInput } from "../../components/SecretInput";
import { useSshLogin } from "../../hooks/useSshLogin";
import { SshLoginFields } from "./SshLoginFields";
import { ServerNetworkPreflight } from "./ServerNetworkPreflight";
import { DialogBack, DialogContent } from "../../components/DialogContent";
import { HashValue } from "../../components/CopyValue";
import { Busy, OperationProgress, OperationResult } from "../../components/OperationResult";
import * as Dialog from "@radix-ui/react-dialog";
import { open } from "../../lib/nativeDialog";
import { Warning } from "@phosphor-icons/react";
import { useEffect, useId, useState } from "react";
import { api } from "../../api";
import {
  useSshHostTrust,
  type InspectedSshHost,
} from "../../hooks/useSshHostTrust";
import { SshHostVerification } from "./SshHostVerification";
import { validateHost } from "../../format";
import { type ServerProfile, type ServerRestoreResult } from "../../types";
import { Field, InlineError } from "../../components/ui";
import { errorMessage } from "../../lib/errors";
import { t } from "../../i18n";
import { Rich } from "../../i18n/Rich";
import { SettingsDisclosure } from "./SettingsParts";

/** The backend's wording for a wrong backup password; only then is the entered password cleared. */
const WRONG_PASSWORD = /password is incorrect/i;

export function VpsRestoreDialog({
  profile,
  open: dialogOpen,
  onOpenChange,
  disconnected,
  onCompleted,
  onReviewAccess,
  onMoveDevices,
}: {
  profile: ServerProfile;
  open: boolean;
  onOpenChange: (open: boolean) => void;
  disconnected: boolean;
  onCompleted: () => Promise<void>;
  onReviewAccess?: () => void;
  onMoveDevices?: () => void;
}) {
  const formId = useId();
  const [step, setStep] = useState<
    "details" | "fingerprint" | "review" | "restoring" | "success"
  >("details");
  const [host, setHost] = useState(profile.endpoint.host);
  const login = useSshLogin(host, dialogOpen);
  const { port } = login;
  const [path, setPath] = useState("");
  const [backupPassword, setBackupPassword] = useState("");
  const trust = useSshHostTrust(host.trim(), Number(port), dialogOpen);
  const [replaceExisting, setReplaceExisting] = useState(false);
  const [confirmed, setConfirmed] = useState(false);
  const [result, setResult] = useState<ServerRestoreResult | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const clearSecrets = () => {
    login.clearSecrets();
    setBackupPassword("");
  };

  const reset = () => {
    clearSecrets();
    setStep("details");
    setHost(profile.endpoint.host);
    setPath("");
    trust.reset();
    setReplaceExisting(false);
    setConfirmed(false);
    setResult(null);
    setBusy(false);
    setError(null);
  };

  useEffect(() => {
    // The dialog stays mounted; default to the endpoint saved when it opens.
    if (dialogOpen) setHost(profile.endpoint.host);
  }, [dialogOpen]);

  const changeOpen = (next: boolean) => {
    if (!next && (busy || step === "restoring")) return;
    onOpenChange(next);
    if (!next) reset();
  };

  const hostValid = validateHost(host);
  const passwordLong = [...backupPassword].length >= 12;
  const valid =
    disconnected &&
    path.length > 0 &&
    passwordLong &&
    hostValid &&
    login.valid;
  const blocker = !disconnected ? t("vps.common.disconnectFirst")
    : !path ? t("vps.restore.missing.file")
    : !passwordLong ? t("vps.restore.missing.password")
    : !hostValid ? t("vps.restore.missing.host")
    : login.missing ?? (step === "fingerprint" && !confirmed ? t("ssh.verify.confirmFirst") : null);

  const chooseSource = async () => {
    try {
      const selected = await open({
        title: t("vps.restore.openDialogTitle"),
        multiple: false,
        directory: false,
        filters: [
          {
            name: t("vps.common.backupFileType"),
            extensions: ["sirinvpn-server-backup"],
          },
        ],
      });
      if (typeof selected === "string") {
        setPath(selected);
        setError(null);
      }
    } catch (reason) {
      setError(
        errorMessage(reason, t("vps.common.error.picker")),
      );
    }
  };

  const inspect = async () => {
    if (!valid) return;
    setBusy(true);
    setError(null);
    try {
      const checked = await trust.inspect();
      if (!checked) return;
      setConfirmed(false);
      setStep(checked.status === "trusted" ? "review" : "fingerprint");
    } catch (reason) {
      setError(
        errorMessage(reason, t("vps.common.error.unreachable")),
      );
    } finally {
      setBusy(false);
    }
  };

  const restore = async (
    checked: InspectedSshHost | null = trust.inspection,
  ) => {
    if (!checked || !valid || (checked.status !== "trusted" && !confirmed))
      return;
    setStep("restoring");
    setBusy(true);
    setError(null);
    try {
      const fingerprint = await trust.accept(checked, confirmed);
      const completed = await api.restoreVpsBackup({
        server_id: profile.id,
        path,
        backup_password: backupPassword,
        host: host.trim(),
        ...(await login.prepare(fingerprint)),
        replace_existing: replaceExisting,
        confirmed: true,
      });
      clearSecrets();
      setResult(completed);
      await onCompleted();
      setStep("success");
    } catch (reason) {
      const message = errorMessage(reason, t("vps.restore.error"));
      // Keep what was entered, except a backup password the file just rejected.
      if (WRONG_PASSWORD.test(message)) setBackupPassword("");
      setConfirmed(false);
      setStep("details");
      setError(message);
    } finally {
      setBusy(false);
    }
  };

  const fileName = path.split(/[\\/]/).pop() ?? path;

  return (
    <Dialog.Root open={dialogOpen} onOpenChange={changeOpen}>
      <Dialog.Portal>
        <Dialog.Overlay className="dialog-overlay" />
        <DialogContent className="dialog-content remove-server-dialog repair-server-dialog vps-restore-dialog"
          heading={t("vps.restore.title", { name: profile.name })}
          description={step === "success" ? t("vps.restore.titleDone") : t("vps.restore.description")}
          closeDisabled={busy || step === "restoring"}
          footerNote={step === "details" || step === "fingerprint" ? busy ? null : blocker : null}
          footer={step === "restoring" ? null
            : step === "success" ? <button className="primary-button" type="button" onClick={() => changeOpen(false)}>{t("common.action.done")}</button>
            : <>
              {step !== "details" && <DialogBack disabled={busy} onClick={() => setStep("details")} />}
              <button className="secondary-button" type="button" disabled={busy} onClick={() => changeOpen(false)}>{t("common.action.cancel")}</button>
              {step === "details" && <button className="primary-button" type="submit" form={formId} disabled={!valid || busy}>{busy ? <Busy label={t("vps.common.checking")} /> : t("vps.restore.review")}</button>}
              {step === "fingerprint" && <button className="primary-button" type="button" disabled={!confirmed || !valid || busy} onClick={() => setStep("review")}>{t("vps.restore.review")}</button>}
              {step === "review" && <button className="primary-button danger-action" type="button" disabled={!valid || busy} onClick={() => void restore()}>{t("vps.restore.action")}</button>}
            </>}>

          {step === "details" ? (
            <form
              className="uninstall-form"
              id={formId}
              onSubmit={(event) => {
                event.preventDefault();
                void inspect();
              }}
            >
              {error ? <InlineError message={error} /> : null}
              <fieldset disabled={busy} className="ssh-operation-fields">
                <div className="sensitive-backup-warning">
                  <Warning size={19} weight="fill" />
                  <p>
                    <Rich id="vps.restore.warning" tags={{ strong: (content) => <strong>{content}</strong> }} />
                  </p>
                </div>
                <Field label={t("vps.restore.file")}>
                  <div className="file-picker-row">
                    <input
                      className="mono"
                      value={path}
                      readOnly
                      placeholder={t("vps.common.noFile")}
                    />
                    <button
                      className="secondary-button"
                      type="button"
                      onClick={() => void chooseSource()}
                      disabled={busy}
                    >
                      {t("vps.common.chooseFile")}
                    </button>
                  </div>
                </Field>
                <Field label={t("vps.common.backupPassword")}>
                  <SecretInput
                    type="password"
                    value={backupPassword}
                    onChange={(event) => setBackupPassword(event.target.value)}
                    autoComplete="off"
                  />
                </Field>
                <Field
                  label={t("vps.restore.host")}
                  hint={t("vps.restore.hostHint")}
                  error={host.trim() && !hostValid ? t("vps.restore.missing.host") : undefined}
                >
                  <input
                    value={host}
                    onChange={(event) => setHost(event.target.value)}
                    autoCapitalize="none"
                    spellCheck={false}
                  />
                </Field>
                <SshLoginFields login={login} />
                <label
                  className={`replacement-option ${replaceExisting ? "selected" : ""}`}
                >
                  <input
                    type="checkbox"
                    checked={replaceExisting}
                    onChange={(event) =>
                      setReplaceExisting(event.target.checked)
                    }
                  />
                  <span>
                    <strong>{t("vps.restore.replace")}</strong>
                    <small>{t("vps.restore.replaceHint")}</small>
                  </span>
                </label>
              </fieldset>
            </form>
          ) : null}

          {step === "fingerprint" && trust.inspection ? (
            <SshHostVerification
              inspection={trust.inspection}
              confirmed={confirmed}
              onConfirmed={setConfirmed}
            />
          ) : null}

          {/* What the restore replaces, said once more before the only button that changes the VPS. */}
          {step === "review" ? (
            <section className="restore-review" aria-labelledby="restore-review-heading">
              <h3 id="restore-review-heading">{t("vps.restore.reviewTitle")}</h3>
              <dl className="result-facts">
                <div><dt>{t("vps.restore.file")}</dt><dd className="mono">{fileName}</dd></div>
                <div><dt>{t("vps.restore.host")}</dt><dd className="mono">{`${host.trim()}:${port}`}</dd></div>
              </dl>
              <div className="danger-note">
                <Warning size={18} weight="fill" />
                <ul>
                  <li>{replaceExisting ? t("vps.restore.consequence.replace") : t("vps.restore.consequence.install")}</li>
                  <li>{t("vps.restore.consequence.access")}</li>
                  <li>{t("vps.restore.consequence.device", { host: host.trim() })}</li>
                </ul>
              </div>
            </section>
          ) : null}

          {step === "restoring" ? <OperationProgress title={t("vps.restore.progress")} /> : null}

          {step === "success" && result ? (
            <OperationResult title={t("vps.restore.done")}>
              <p>{t("vps.restore.doneNote", { host: result.profile.endpoint.host })}</p>
              {(onReviewAccess || onMoveDevices) && <div className="operation-result-actions">
                {onReviewAccess && <button type="button" className="secondary-button" onClick={() => { changeOpen(false); onReviewAccess(); }}>{t("vps.restore.reviewAccess")}</button>}
                {onMoveDevices && <button type="button" className="secondary-button" onClick={() => { changeOpen(false); onMoveDevices(); }}>{t("vps.restore.moveDevices")}</button>}
              </div>}
              {result.network_preflight && <ServerNetworkPreflight report={result.network_preflight} />}
              <SettingsDisclosure className="result-disclosure" summary={t("vps.common.softwareDetails")}>
                <HashValue label={t("vps.common.softwareHash")} value={result.artifact_sha256} />
              </SettingsDisclosure>
            </OperationResult>
          ) : null}
        </DialogContent>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
