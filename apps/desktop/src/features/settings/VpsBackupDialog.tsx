import { SecretInput } from "../../components/SecretInput";
import { ShareEncryptedFile } from "../../components/ShareEncryptedFile";
import { useSshLogin } from "../../hooks/useSshLogin";
import { SshLoginFields } from "./SshLoginFields";
import { DialogBack, DialogContent } from "../../components/DialogContent";
import { HashValue } from "../../components/CopyValue";
import { Busy, OperationProgress, OperationResult } from "../../components/OperationResult";
import * as Dialog from "@radix-ui/react-dialog";
import { save } from "../../lib/nativeDialog";
import { GlobeHemisphereWest, Warning } from "@phosphor-icons/react";
import { useId, useState } from "react";
import { api } from "../../api";
import {
  useSshHostTrust,
  type InspectedSshHost,
} from "../../hooks/useSshHostTrust";
import { SshHostVerification } from "./SshHostVerification";
import { type ServerBackupResult, type ServerProfile } from "../../types";
import { Field, InlineError } from "../../components/ui";
import { preferredBackupPath } from "../../lib/backupPaths";
import { errorMessage } from "../../lib/errors";
import { t } from "../../i18n";
import { Rich } from "../../i18n/Rich";

export function VpsBackupDialog({
  profile,
  open: dialogOpen,
  onOpenChange,
  disconnected,
}: {
  profile: ServerProfile;
  open: boolean;
  onOpenChange: (open: boolean) => void;
  disconnected: boolean;
}) {
  const formId = useId();
  const [step, setStep] = useState<
    "details" | "fingerprint" | "exporting" | "success"
  >("details");
  const login = useSshLogin(profile.endpoint.host, dialogOpen);
  const { port } = login;
  const [path, setPath] = useState("");
  const [backupPassword, setBackupPassword] = useState("");
  const [backupPasswordConfirmation, setBackupPasswordConfirmation] =
    useState("");
  const trust = useSshHostTrust(
    profile.endpoint.host,
    Number(port),
    dialogOpen,
  );
  const [confirmed, setConfirmed] = useState(false);
  const [result, setResult] = useState<ServerBackupResult | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const clearSecrets = () => {
    login.clearSecrets();
    setBackupPassword("");
    setBackupPasswordConfirmation("");
  };

  const reset = () => {
    clearSecrets();
    setStep("details");
    setPath("");
    trust.reset();
    setConfirmed(false);
    setResult(null);
    setBusy(false);
    setError(null);
  };

  const changeOpen = (next: boolean) => {
    if (!next && (busy || step === "exporting")) return;
    onOpenChange(next);
    if (!next) reset();
  };

  const passwordLong = [...backupPassword].length >= 12;
  const passwordsMatch = passwordLong && backupPassword === backupPasswordConfirmation;
  const valid =
    disconnected && path.length > 0 && login.valid && passwordsMatch;
  const blocker = !disconnected ? t("vps.common.disconnectFirst")
    : !path ? t("vps.backup.missing.file")
    : !passwordLong ? t("vps.backup.missing.password")
    : !passwordsMatch ? t("vps.backup.missing.repeat")
    : login.missing ?? (step === "fingerprint" && !confirmed ? t("ssh.verify.confirmFirst") : null);

  const chooseDestination = async () => {
    try {
      const safeName =
        profile.name
          .trim()
          .replace(/[^a-zA-Z0-9_-]+/g, "-")
          .replace(/^-+|-+$/g, "") || "sirinvpn-vps";
      const selected = await save({
        title: t("vps.backup.saveDialogTitle"),
        defaultPath: await preferredBackupPath(
          `${safeName}.sirinvpn-server-backup`,
        ),
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
      if (checked.status === "trusted") {
        await exportBackup(checked);
      } else {
        setStep("fingerprint");
      }
    } catch (reason) {
      setError(errorMessage(reason, t("vps.common.error.unreachable")));
    } finally {
      setBusy(false);
    }
  };

  const exportBackup = async (
    checked: InspectedSshHost | null = trust.inspection,
  ) => {
    if (!checked || !valid || (checked.status !== "trusted" && !confirmed))
      return;
    setStep("exporting");
    setBusy(true);
    setError(null);
    try {
      const fingerprint = await trust.accept(checked, confirmed);
      const completed = await api.exportVpsBackup({
        server_id: profile.id,
        path,
        backup_password: backupPassword,
        ...(await login.prepare(fingerprint)),
        confirmed: true,
      });
      clearSecrets();
      setResult(completed);
      setStep("success");
    } catch (reason) {
      // The passwords the user chose stay entered: this failure says nothing about them.
      setConfirmed(false);
      setStep("details");
      setError(
        errorMessage(reason, t("vps.backup.error")),
      );
    } finally {
      setBusy(false);
    }
  };

  return (
    <Dialog.Root open={dialogOpen} onOpenChange={changeOpen}>
      <Dialog.Portal>
        <Dialog.Overlay className="dialog-overlay" />
        <DialogContent className="dialog-content remove-server-dialog repair-server-dialog vps-backup-dialog"
          heading={t("vps.backup.title", { name: profile.name })}
          description={step === "success" ? t("vps.backup.titleDone") : t("vps.backup.description")}
          closeDisabled={busy || step === "exporting"}
          footerNote={step === "details" || step === "fingerprint" ? busy ? null : blocker : null}
          footer={step === "exporting" ? null
            : step === "success" ? <button className="primary-button" type="button" onClick={() => changeOpen(false)}>{t("common.action.done")}</button>
            : <>
              {step === "fingerprint" && <DialogBack disabled={busy} onClick={() => setStep("details")} />}
              <button className="secondary-button" type="button" disabled={busy} onClick={() => changeOpen(false)}>{t("common.action.cancel")}</button>
              {step === "details"
                ? <button className="primary-button" type="submit" form={formId} disabled={!valid || busy}>{busy ? <Busy label={t("vps.common.checking")} /> : t("vps.backup.create")}</button>
                : <button className="primary-button" type="button" disabled={!confirmed || !valid || busy} onClick={() => void exportBackup()}>{t("vps.backup.create")}</button>}
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
                    <Rich id="vps.backup.warning" tags={{ strong: (content) => <strong>{content}</strong> }} />
                  </p>
                </div>
                <div className="uninstall-target">
                  <GlobeHemisphereWest size={16} />
                  <code>{profile.endpoint.host}</code>
                </div>
                <Field
                  label={t("vps.backup.destination")}
                  hint={t("vps.backup.destinationHint")}
                >
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
                      onClick={() => void chooseDestination()}
                      disabled={busy}
                    >
                      {t("vps.common.chooseFile")}
                    </button>
                  </div>
                </Field>
                <div className="field-grid two-column backup-passwords">
                  <Field
                    label={t("vps.common.backupPassword")}
                    hint={t("vps.backup.passwordHint")}
                  >
                    <SecretInput
                      type="password"
                      value={backupPassword}
                      onChange={(event) =>
                        setBackupPassword(event.target.value)
                      }
                      autoComplete="new-password"
                    />
                  </Field>
                  <Field label={t("vps.backup.repeatPassword")}
                    hint={passwordsMatch ? t("vps.common.passwordsMatch") : undefined}
                    error={backupPasswordConfirmation && backupPasswordConfirmation !== backupPassword ? t("common.error.passwordsDiffer") : undefined}>
                    <SecretInput
                      type="password"
                      value={backupPasswordConfirmation}
                      onChange={(event) =>
                        setBackupPasswordConfirmation(event.target.value)
                      }
                      autoComplete="new-password"
                    />
                  </Field>
                </div>
                <SshLoginFields login={login} />
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

          {step === "exporting" ? <OperationProgress title={t("vps.backup.progress")} /> : null}

          {step === "success" && result ? (
            <OperationResult title={t("vps.backup.done")}>
              <p className="operation-result-path">{path}</p>
              <p>{t("vps.backup.doneNote")}</p>
              <ShareEncryptedFile uri={path} />
              {/* The hash is of the helper the VPS ran to read its state, not of the backup file. */}
              <details className="result-disclosure"><summary>{t("vps.common.softwareDetails")}</summary>
                <HashValue label={t("vps.common.softwareHash")} value={result.artifact_sha256} />
              </details>
            </OperationResult>
          ) : null}
        </DialogContent>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
