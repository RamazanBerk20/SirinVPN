import { SecretInput } from "../../components/SecretInput";
import { open } from "../../lib/nativeDialog";
import { ArrowClockwise, LockKey, UploadSimple } from "@phosphor-icons/react";
import { useState } from "react";
import { api } from "../../api";
import { type ServerProfile } from "../../types";
import { Field, InlineError } from "../../components/ui";
import { preferredBackupDirectory } from "../../lib/backupPaths";
import { errorMessage } from "../../lib/errors";

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
        title: "Open encrypted SirinVPN backup",
        multiple: false,
        directory: false,
        defaultPath,
        filters: [
          {
            name: "SirinVPN encrypted backup",
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
        errorMessage(reason, "The backup file picker could not be opened."),
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
        errorMessage(
          reason,
          "The encrypted device backup could not be restored.",
        ),
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
          <h2>Restore this device</h2>
          <p>
            Decrypt one local profile and device identity. The VPS is not
            contacted or changed.
          </p>
        </div>
      </div>
      <Field
        label="Encrypted backup"
        hint="Existing identities and conflicting server IDs are never overwritten."
      >
        <div className="file-picker-row">
          <input
            className="mono"
            value={path}
            readOnly
            placeholder="Choose a .sirinvpn-backup file"
          />
          <button
            className="secondary-button"
            type="button"
            onClick={() => void chooseBackup()}
            disabled={busy}
          >
            Choose file
          </button>
        </div>
      </Field>
      <Field label="Backup password">
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
        {busy ? "Decrypting locally" : "Restore backup"}
      </button>
      <p className="form-footnote">
        <LockKey size={15} /> Passwords and decrypted keys are never sent to a
        server.
      </p>
    </form>
  );
}
