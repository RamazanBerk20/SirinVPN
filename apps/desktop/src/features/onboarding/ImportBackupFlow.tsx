import { SecretInput } from "../../components/SecretInput";
import { open } from "../../lib/nativeDialog";
import { ArrowClockwise, UploadSimple } from "@phosphor-icons/react";
import { useState } from "react";
import { api } from "../../api";
import { type ServerProfile } from "../../types";
import { Field, InlineError } from "../../components/ui";
import { preferredBackupDirectory } from "../../lib/backupPaths";
import { errorMessage } from "../../lib/errors";
import { t } from "../../i18n";

export function ImportBackupFlow({
  onComplete,
  compact = false,
}: {
  onComplete: (profile: ServerProfile) => Promise<void>;
  compact?: boolean;
}) {
  const [path, setPath] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const chooseBackup = async () => {
    try {
      const defaultPath = await preferredBackupDirectory();
      const selected = await open({
        title: t("onboarding.backup.pickerTitle"),
        multiple: false,
        directory: false,
        defaultPath,
        filters: [
          {
            name: t("onboarding.backup.fileType"),
            extensions: ["sirinvpn-backup"],
          },
        ],
      });
      if (typeof selected === "string") {
        setPath(selected);
        setError(null);
      }
    } catch (reason) {
      setError(
        errorMessage(reason, t("onboarding.backup.error.picker")),
      );
    }
  };

  const restore = async () => {
    if (!path || !password) return;
    setBusy(true);
    setError(null);
    try {
      const profile = await api.importServerBackup(path, password);
      setPassword("");
      setPath("");
      await onComplete(profile);
    } catch (reason) {
      setPassword("");
      setError(
        errorMessage(reason, t("onboarding.backup.error.restore")),
      );
    } finally {
      setBusy(false);
    }
  };

  return (
    <form
      className={`setup-form backup-import-form ${compact ? "compact" : ""}`}
      onSubmit={(event) => {
        event.preventDefault();
        void restore();
      }}
    >
      <div className="form-heading">
        <span>
          <UploadSimple size={20} />
        </span>
        <div>
          <h2>{t("onboarding.backup.title")}</h2>
          <p>{t("onboarding.backup.summary")}</p>
        </div>
      </div>
      <Field
        label={t("onboarding.backup.file")}
        hint={t("onboarding.backup.fileHint")}
      >
        <div className="file-picker-row">
          <input
            className="mono"
            value={path}
            readOnly
            placeholder={t("onboarding.backup.filePlaceholder")}
          />
          <button
            className="secondary-button"
            type="button"
            onClick={() => void chooseBackup()}
            disabled={busy}
          >
            {t("onboarding.backup.choose")}
          </button>
        </div>
      </Field>
      <Field label={t("onboarding.backup.password")}>
        <SecretInput
          type="password"
          value={password}
          onChange={(event) => setPassword(event.target.value)}
          autoComplete="off"
        />
      </Field>
      {error ? <InlineError message={error} /> : null}
      <button
        className="primary-button"
        type="submit"
        disabled={busy || !path || !password}
      >
        {busy ? (
          <ArrowClockwise className="spin" size={18} />
        ) : (
          <UploadSimple size={18} />
        )}
        {busy ? t("onboarding.backup.submitting") : t("onboarding.backup.submit")}
      </button>
    </form>
  );
}
