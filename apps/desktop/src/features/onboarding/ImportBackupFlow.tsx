import { SecretInput } from "../../components/SecretInput";
import { open } from "../../lib/nativeDialog";
import { ArrowClockwise, FileArrowUp, UploadSimple } from "@phosphor-icons/react";
import { useState } from "react";
import { api } from "../../api";
import { type ServerProfile } from "../../types";
import { Field, InlineError } from "../../components/ui";
import { preferredBackupDirectory } from "../../lib/backupPaths";
import { errorMessage } from "../../lib/errors";
import { notify } from "../../components/Toasts";
import { t } from "../../i18n";

/** The file name of a chosen path or Android document address, for display; the full path stays in the tooltip. */
export function fileName(path: string): string {
  let decoded = path;
  try { decoded = decodeURIComponent(path); } catch { /* keep the raw path */ }
  return decoded.split(/[\\/:]/).filter(Boolean).pop() ?? path;
}

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
        purpose: "backup_import",
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
      notify(t("onboarding.backup.restored", { name: profile.name }));
      await onComplete(profile);
    } catch (reason) {
      // Keep the password: most failures (a duplicate identity, a newer format, a write error) aren't about it.
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
      <div className="field">
        <span>{t("onboarding.backup.file")}</span>
        {/* One picker row: the chosen file name, or what to choose; the whole row opens the picker. */}
        <button
          type="button"
          className={`file-pick ${path ? "chosen" : ""}`}
          title={path || undefined}
          aria-describedby="backup-file-hint"
          onClick={() => void chooseBackup()}
          disabled={busy}
        >
          <FileArrowUp size={22} aria-hidden="true" />
          <span>
            <strong>{path ? fileName(path) : t("onboarding.backup.choose")}</strong>
            {path && <small>{t("onboarding.backup.change")}</small>}
          </span>
        </button>
        <small id="backup-file-hint">{t("onboarding.backup.fileHint")}</small>
      </div>
      <Field label={t("onboarding.backup.password")}>
        <SecretInput field="password"
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
