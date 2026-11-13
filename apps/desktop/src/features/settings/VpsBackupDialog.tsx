import { SecretInput } from "../../components/SecretInput";
import { ShareEncryptedFile } from "../../components/ShareEncryptedFile";
import { useSshOperation } from "../../hooks/useSshOperation";
import { SshLoginFields } from "./SshLoginFields";
import { DialogBack, DialogContent } from "../../components/DialogContent";
import { HashValue } from "../../components/CopyValue";
import { Busy, OperationProgress, OperationResult, stepsAt } from "../../components/OperationResult";
import * as Dialog from "@radix-ui/react-dialog";
import { save } from "../../lib/nativeDialog";
import { GlobeHemisphereWest, Warning } from "@phosphor-icons/react";
import { useId, useState } from "react";
import { api } from "../../api";
import type { InspectedSshHost } from "../../hooks/useSshHostTrust";
import { SshHostVerification } from "./SshHostVerification";
import { type ServerBackupResult, type ServerProfile } from "../../types";
import { Field } from "../../components/ui";
import { ServerChangeFailure } from "../../components/ServerChange";
import { preferredBackupPath } from "../../lib/backupPaths";
import { errorMessage } from "../../lib/errors";
import { t } from "../../i18n";
import { Rich } from "../../i18n/Rich";
import { SettingsDisclosure } from "./SettingsParts";

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
  const op = useSshOperation<ServerBackupResult>(profile.endpoint.host, dialogOpen);
  const { login, trust, view: step, busy, phase, result } = op;
  const [path, setPath] = useState("");
  const [pickerError, setPickerError] = useState<string | null>(null);
  const error = op.error ?? pickerError;
  const [backupPassword, setBackupPassword] = useState("");
  const [backupPasswordConfirmation, setBackupPasswordConfirmation] =
    useState("");

  const reset = () => {
    op.reset();
    setBackupPassword("");
    setBackupPasswordConfirmation("");
    setPath("");
    setPickerError(null);
  };

  const changeOpen = (next: boolean) => {
    if (!next && busy) return;
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
    : login.missing ?? (step === "confirmHost" && !trust.confirmed ? t("ssh.verify.confirmFirst") : null);

  const chooseDestination = async () => {
    try {
      // Letters and digits of any script stay; a non-Latin name must not become the generic default.
      const safeName =
        profile.name
          .trim()
          .replace(/[^\p{L}\p{N}_-]+/gu, "-")
          .replace(/^-+|-+$/g, "") || "sirinvpn-vps";
      const selected = await save({
        purpose: "vps_backup_export",
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
        setPickerError(null);
      }
    } catch (reason) {
      setPickerError(errorMessage(reason, t("vps.common.error.picker")));
    }
  };

  const inspect = async () => {
    if (!valid) return;
    setPickerError(null);
    await op.verify(t("vps.common.error.unreachable"), exportBackup);
  };

  const exportBackup = async (checked: InspectedSshHost | null = trust.inspection) => {
    if (!checked || !valid || (checked.status !== "trusted" && !trust.confirmed)) return;
    // On failure the passwords the user chose stay entered: it says nothing about them.
    await op.run(async credentials => {
      const completed = await api.exportVpsBackup({
        server_id: profile.id,
        path,
        backup_password: backupPassword,
        ...credentials,
        confirmed: true,
      });
      setBackupPassword("");
      setBackupPasswordConfirmation("");
      return completed;
    }, t("vps.backup.error"), { inspection: checked });
  };

  return (
    <Dialog.Root open={dialogOpen} onOpenChange={changeOpen}>
      <Dialog.Portal>
        <Dialog.Overlay className="dialog-overlay" />
        <DialogContent className="dialog-content remove-server-dialog repair-server-dialog vps-backup-dialog"
          heading={t("vps.backup.title", { name: profile.name })}
          data-operation="backup" data-flow-state={op.state.kind}
          description={step === "succeeded" ? t("vps.backup.titleDone") : t("vps.backup.description")}
          closeDisabled={busy}
          footerNote={step === "form" || step === "confirmHost" ? busy ? null : blocker : null}
          footer={step === "running" ? null
            : step === "succeeded" ? <button className="primary-button" type="button" onClick={() => changeOpen(false)}>{t("common.action.done")}</button>
            : <>
              {step === "confirmHost" && <DialogBack disabled={busy} onClick={op.back} />}
              <button className="secondary-button" type="button" disabled={busy} onClick={() => changeOpen(false)}>{t("common.action.cancel")}</button>
              {step === "form"
                ? <button className="primary-button" type="submit" form={formId} disabled={!valid || busy}>{busy ? <Busy label={t("vps.common.checking")} /> : t("vps.backup.create")}</button>
                : <button className="primary-button" type="button" disabled={!trust.confirmed || !valid || busy} onClick={() => void exportBackup()}>{t("vps.backup.create")}</button>}
            </>}>

          {step === "form" ? (
            <form
              className="uninstall-form"
              id={formId}
              onSubmit={(event) => {
                event.preventDefault();
                void inspect();
              }}
            >
              <ServerChangeFailure reason={op.failure} message={error} />
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
                    <SecretInput field="backup_password"
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
                    <SecretInput field="backup_password"
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

          {step === "confirmHost" && trust.inspection ? (
            <SshHostVerification
              inspection={trust.inspection}
              confirmed={trust.confirmed}
              onConfirmed={trust.setConfirmed}
            />
          ) : null}

          {step === "running" ? <OperationProgress title={t("vps.backup.progress")}
            steps={stepsAt([t("vps.common.step.identity"), t("vps.backup.step")], phase)} /> : null}

          {result ? (
            <OperationResult title={t("vps.backup.done")}>
              <p className="operation-result-path">{path}</p>
              <p>{t("vps.backup.doneNote")}</p>
              <ShareEncryptedFile uri={path} />
              {/* The hash is of the helper the VPS ran to read its state, not of the backup file. */}
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
