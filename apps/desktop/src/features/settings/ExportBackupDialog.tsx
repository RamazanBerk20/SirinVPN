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
        title: "Save encrypted SirinVPN backup",
        defaultPath: await preferredBackupPath(`${safeName}.sirinvpn-backup`),
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
        errorMessage(
          reason,
          "The backup destination picker could not be opened.",
        ),
      );
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
      setError(
        errorMessage(
          reason,
          "The encrypted device backup could not be created.",
        ),
      );
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
          heading={<>Encrypted device backup</>}
          description={<>Export this local profile and its private WireGuard and management
            identity. Nothing is uploaded.</>}
          closeDisabled={busy} closeLabel="Close">
          {complete ? (
            <div className="backup-success">
              <span>
                <Check size={24} weight="bold" />
              </span>
              <h3>Backup created</h3>
              <ShareEncryptedFile uri={path} />
              <p>
                Store the file and its password separately. Restoring it does
                not change your VPS.
              </p>
              <button
                className="primary-button"
                type="button"
                onClick={() => changeOpen(false)}
              >
                Done
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
                  <strong>This file can impersonate this device.</strong> Anyone
                  with both the file and password can connect until the device
                  is revoked.
                </p>
              </div>
              <Field
                label="Save destination"
                hint="SirinVPN refuses to overwrite an existing file."
              >
                <div className="file-picker-row">
                  <input
                    className="mono"
                    value={path}
                    readOnly
                    placeholder="Choose a protected destination"
                  />
                  <button
                    className="secondary-button"
                    type="button"
                    onClick={() => void chooseDestination()}
                    disabled={busy}
                  >
                    Choose file
                  </button>
                </div>
              </Field>
              <div className="field-grid two-column backup-passwords">
                <Field label="Password" hint="Use at least 12 characters.">
                  <SecretInput
                    type="password"
                    value={password}
                    onChange={(event) => setPassword(event.target.value)}
                    autoComplete="new-password"
                  />
                </Field>
                <Field label="Repeat password">
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
                  <strong>
                    I understand this export contains a complete private device
                    identity.
                  </strong>
                  <small>
                    The password cannot be recovered by SirinVPN or anyone else.
                  </small>
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
                {busy ? "Encrypting locally" : "Create encrypted backup"}
              </button>
            </form>
          )}
        </DialogContent>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
