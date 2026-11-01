import { SecretInput } from "../../components/SecretInput";
import { ShareEncryptedFile } from "../../components/ShareEncryptedFile";
import { DialogContent } from "../../components/DialogContent";
import * as Dialog from "@radix-ui/react-dialog";
import { save } from "../../lib/nativeDialog";
import {
  ArrowClockwise,
  Check,
  DownloadSimple,
  Warning,
} from "@phosphor-icons/react";
import { useState } from "react";
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
  const [path, setPath] = useState("");
  const [password, setPassword] = useState("");
  const [passwordConfirmation, setPasswordConfirmation] = useState("");
  const [confirmed, setConfirmed] = useState(false);
  const [busy, setBusy] = useState(false);
  const [complete, setComplete] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const passwordValid =
    [...password].length >= 12 && password === passwordConfirmation;

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
      setComplete(true);
    } catch (reason) {
      setError(errorMessage(reason, t("settings.backup.failed")));
    } finally {
      setPassword("");
      setPasswordConfirmation("");
      setBusy(false);
    }
  };

  return (
    <Dialog.Root open={dialogOpen} onOpenChange={changeOpen}>
      <Dialog.Portal>
        <Dialog.Overlay className="dialog-overlay" />
        <DialogContent className="dialog-content backup-dialog"
          heading={<>{t("settings.backup.title")}</>}
          description={<>{t("settings.backup.description")}</>}
          closeDisabled={busy} closeLabel={t("common.action.close")}>
          {complete ? (
            <div className="backup-success">
              <span>
                <Check size={24} weight="bold" />
              </span>
              <h3>{t("settings.backup.done.title")}</h3>
              <ShareEncryptedFile uri={path} />
              <p>{t("settings.backup.done.summary")}</p>
              <button
                className="primary-button"
                type="button"
                onClick={() => changeOpen(false)}
              >
                {t("common.action.done")}
              </button>
            </div>
          ) : (
            <form
              className="backup-form"
              onSubmit={(event) => {
                event.preventDefault();
                void exportBackup();
              }}
            >
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
                    disabled={busy}
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
                <Field label={t("settings.backup.password.repeat")} error={passwordConfirmation && passwordConfirmation !== password ? t("common.error.passwordsDiffer") : undefined}>
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
              <label
                className={`replacement-option backup-confirmation ${confirmed ? "selected" : ""}`}
              >
                <input
                  type="checkbox"
                  checked={confirmed}
                  onChange={(event) => setConfirmed(event.target.checked)}
                />
                <span>
                  <strong>{t("settings.backup.accept.label")}</strong>
                  <small>{t("settings.backup.accept.hint")}</small>
                </span>
              </label>
              {error ? <InlineError message={error} /> : null}
              <button
                className="primary-button"
                type="submit"
                disabled={busy || !path || !passwordValid || !confirmed}
              >
                {busy ? (
                  <ArrowClockwise className="spin" size={18} />
                ) : (
                  <DownloadSimple size={18} />
                )}
                {busy ? t("settings.backup.creating") : t("settings.backup.create")}
              </button>
            </form>
          )}
        </DialogContent>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
