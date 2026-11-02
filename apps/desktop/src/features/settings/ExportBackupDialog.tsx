import { SecretInput } from "../../components/SecretInput";
import { ShareEncryptedFile } from "../../components/ShareEncryptedFile";
import { DialogContent } from "../../components/DialogContent";
import { ConfirmationRow } from "../../components/ConfirmationRow";
import { Busy, OperationResult } from "../../components/OperationResult";
import * as Dialog from "@radix-ui/react-dialog";
import { save } from "../../lib/nativeDialog";
import { Warning } from "@phosphor-icons/react";
import { useId, useState } from "react";
import { api } from "../../api";
import { type ServerProfile } from "../../types";
import { Field, InlineError } from "../../components/ui";
import { preferredBackupPath } from "../../lib/backupPaths";
import { errorMessage } from "../../lib/errors";
import { t } from "../../i18n";
import { Rich } from "../../i18n/Rich";

export function ExportBackupDialog({
  profile,
  open: dialogOpen,
  onOpenChange,
}: {
  profile: ServerProfile;
  open: boolean;
  onOpenChange: (open: boolean) => void;
}) {
  const formId = useId();
  const [path, setPath] = useState("");
  const [password, setPassword] = useState("");
  const [passwordConfirmation, setPasswordConfirmation] = useState("");
  const [confirmed, setConfirmed] = useState(false);
  const [busy, setBusy] = useState(false);
  const [complete, setComplete] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const passwordLong = [...password].length >= 12;
  const passwordValid = passwordLong && password === passwordConfirmation;
  const blocker = !path ? t("vps.backup.missing.file")
    : !passwordLong ? t("vps.backup.missing.password")
    : !passwordValid ? t("vps.backup.missing.repeat")
    : !confirmed ? t("vps.deviceBackup.confirmFirst") : null;

  const reset = () => {
    setPath("");
    setPassword("");
    setPasswordConfirmation("");
    setConfirmed(false);
    setBusy(false);
    setComplete(false);
    setError(null);
  };

  const changeOpen = (next: boolean) => {
    if (!next && busy) return;
    onOpenChange(next);
    if (!next) reset();
  };

  const chooseDestination = async () => {
    try {
      const safeName =
        profile.name
          .trim()
          .replace(/[^a-zA-Z0-9_-]+/g, "-")
          .replace(/^-+|-+$/g, "") || "sirinvpn-device";
      const selected = await save({
        title: t("settings.backup.dialogTitle"),
        defaultPath: await preferredBackupPath(`${safeName}.sirinvpn-backup`),
        filters: [
          {
            name: t("settings.backup.fileType"),
            extensions: ["sirinvpn-backup"],
          },
        ],
      });
      if (typeof selected === "string") {
        setPath(selected);
        setError(null);
      }
    } catch (reason) {
      setError(errorMessage(reason, t("settings.backup.pickerFailed")));
    }
  };

  const exportBackup = async () => {
    if (!path || !passwordValid || !confirmed) return;
    setBusy(true);
    setError(null);
    try {
      await api.exportServerBackup(profile.id, path, password, confirmed);
      setPassword("");
      setPasswordConfirmation("");
      setComplete(true);
    } catch (reason) {
      // A write failure says nothing about the password, so it stays entered for Try again.
      setError(errorMessage(reason, t("settings.backup.failed")));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Dialog.Root open={dialogOpen} onOpenChange={changeOpen}>
      <Dialog.Portal>
        <Dialog.Overlay className="dialog-overlay" />
        <DialogContent className="dialog-content backup-dialog"
          heading={t("settings.backup.title")}
          description={complete ? t("settings.backup.done.title") : t("settings.backup.description")}
          closeDisabled={busy} closeLabel={t("common.action.close")}
          footerNote={complete || busy ? null : blocker}
          footer={complete
            ? <button className="primary-button" type="button" onClick={() => changeOpen(false)}>{t("common.action.done")}</button>
            : <>
              <button className="secondary-button" type="button" disabled={busy} onClick={() => changeOpen(false)}>{t("common.action.cancel")}</button>
              <button className="primary-button" type="submit" form={formId} disabled={busy || Boolean(blocker)}>
                {busy ? <Busy label={t("settings.backup.creating")} /> : t("settings.backup.create")}
              </button>
            </>}>
          {complete ? (
            <OperationResult title={t("settings.backup.done.title")}>
              <p className="operation-result-path">{path}</p>
              <p>{t("settings.backup.done.summary")}</p>
              <ShareEncryptedFile uri={path} />
            </OperationResult>
          ) : (
            <form
              className="backup-form"
              id={formId}
              onSubmit={(event) => {
                event.preventDefault();
                void exportBackup();
              }}
            >
              {error ? <InlineError message={error} /> : null}
              <fieldset disabled={busy} className="ssh-operation-fields">
                <div className="sensitive-backup-warning">
                  <Warning size={19} weight="fill" />
                  <p>
                    <Rich id="settings.backup.warning" tags={{ strong: content => <strong>{content}</strong> }} />
                  </p>
                </div>
                <Field
                  label={t("settings.backup.destination.label")}
                  hint={t("settings.backup.destination.hint")}
                >
                  <div className="file-picker-row">
                    <input
                      className="mono"
                      value={path}
                      readOnly
                      placeholder={t("settings.backup.destination.placeholder")}
                    />
                    <button
                      className="secondary-button"
                      type="button"
                      onClick={() => void chooseDestination()}
                    >
                      {t("settings.backup.destination.choose")}
                    </button>
                  </div>
                </Field>
                <div className="field-grid two-column backup-passwords">
                  <Field label={t("settings.backup.password.label")} hint={t("settings.backup.password.hint")}>
                    <SecretInput
                      type="password"
                      value={password}
                      onChange={(event) => setPassword(event.target.value)}
                      autoComplete="new-password"
                    />
                  </Field>
                  <Field label={t("settings.backup.password.repeat")}
                    hint={passwordValid ? t("vps.common.passwordsMatch") : undefined}
                    error={passwordConfirmation && passwordConfirmation !== password ? t("common.error.passwordsDiffer") : undefined}>
                    <SecretInput
                      type="password"
                      value={passwordConfirmation}
                      onChange={(event) =>
                        setPasswordConfirmation(event.target.value)
                      }
                      autoComplete="new-password"
                    />
                  </Field>
                </div>
                <ConfirmationRow checked={confirmed} onChange={setConfirmed}>
                  <strong>{t("settings.backup.accept.label")}</strong>
                  <small>{t("settings.backup.accept.hint")}</small>
                </ConfirmationRow>
              </fieldset>
            </form>
          )}
        </DialogContent>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
