import { SecretInput } from "../../components/SecretInput";
import { ShareEncryptedFile } from "../../components/ShareEncryptedFile";
import { useSshLogin } from "../../hooks/useSshLogin";
import { SshLoginFields } from "./SshLoginFields";
import { DialogContent } from "../../components/DialogContent";
import * as Dialog from "@radix-ui/react-dialog";
import { save } from "../../lib/nativeDialog";
import {
  ArrowClockwise,
  Check,
  DownloadSimple,
  GlobeHemisphereWest,
  Warning,
} from "@phosphor-icons/react";
import { useState } from "react";
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

  const backupPasswordValid =
    [...backupPassword].length >= 12 &&
    backupPassword === backupPasswordConfirmation;
  const valid =
    disconnected && path.length > 0 && login.valid && backupPasswordValid;

  const chooseDestination = async () => {
    try {
      const safeName =
        profile.name
          .trim()
          .replace(/[^a-zA-Z0-9_-]+/g, "-")
          .replace(/^-+|-+$/g, "") || "sirinvpn-vps";
      const selected = await save({
        title: "Save encrypted SirinVPN VPS backup",
        defaultPath: await preferredBackupPath(
          `${safeName}.sirinvpn-server-backup`,
        ),
        filters: [
          {
            name: "SirinVPN encrypted VPS backup",
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
        errorMessage(
          reason,
          "The VPS backup destination picker could not be opened.",
        ),
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
      setError(errorMessage(reason, "The VPS could not be reached over SSH."));
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
      clearSecrets();
      setConfirmed(false);
      setStep("details");
      setError(
        errorMessage(reason, "The encrypted VPS backup could not be created."),
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
          heading={<>{step === "exporting"
              ? "Encrypting VPS state"
              : step === "success"
                ? "VPS backup complete"
                : `Back up ${profile.name}`}</>}
          description={<>Export the current SirinVPN server identity, authorization, DNS, and
            transport state through pinned SSH for guarded recovery or
            migration.</>}
          closeDisabled={busy || step === "exporting"} closeLabel="Close">

          {step === "details" ? (
            <form
              className="uninstall-form"
              onSubmit={(event) => {
                event.preventDefault();
                void inspect();
              }}
            >
              <fieldset disabled={busy} className="ssh-operation-fields">
                <div className="sensitive-backup-warning">
                  <Warning size={19} weight="fill" />
                  <p>
                    <strong>This file can clone the VPS identity.</strong> Store
                    it and its password separately. It does not include this
                    device's private identity.
                  </p>
                </div>
                <div className="uninstall-target">
                  <GlobeHemisphereWest size={16} />
                  <code>{profile.endpoint.host}</code>
                </div>
                {!disconnected ? (
                  <InlineError message="Disconnect every active SirinVPN tunnel before backing up this VPS." />
                ) : null}
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
                  <Field
                    label="Backup password"
                    hint="Use at least 12 characters."
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
                  <Field label="Repeat password">
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
                {error ? <InlineError message={error} /> : null}
                <button
                  className="primary-button"
                  type="submit"
                  disabled={!valid || busy}
                >
                  {busy ? "Checking VPS" : "Create VPS backup"}
                </button>
              </fieldset>
            </form>
          ) : null}

          {step === "fingerprint" && trust.inspection ? (
            <div className="uninstall-fingerprint repair-fingerprint">
              <button
                className="back-button"
                onClick={() => setStep("details")}
              >
                Back
              </button>
              <SshHostVerification
                inspection={trust.inspection}
                confirmed={confirmed}
                onConfirmed={setConfirmed}
              />
              <button
                className="primary-button"
                disabled={!confirmed || busy}
                onClick={() => void exportBackup()}
              >
                <DownloadSimple size={18} /> Create VPS backup
              </button>
            </div>
          ) : null}

          {step === "exporting" ? (
            <div className="uninstall-progress repair-progress">
              <ArrowClockwise className="spin" size={26} />
              <strong>Validating and encrypting current state</strong>
              <p>
                Keep the app open. This read-only operation does not stop or
                reconfigure the VPS.
              </p>
            </div>
          ) : null}

          {step === "success" && result ? (
            <div className="backup-success repair-success">
              <span>
                <Check size={26} weight="bold" />
              </span>
              <h3>Encrypted VPS backup created</h3>
              <ShareEncryptedFile uri={path} />
              <p>
                Current server identity and authorization were validated with
                the packaged server component. Store the file and password
                separately.
              </p>
              <code>{result.artifact_sha256}</code>
              <button
                className="primary-button"
                onClick={() => changeOpen(false)}
              >
                Done
              </button>
            </div>
          ) : null}
        </DialogContent>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
