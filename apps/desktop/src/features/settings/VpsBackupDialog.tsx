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
      clearSecrets();
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
          heading={<>{step === "exporting"
              ? t("vps.backup.titleRunning")
              : step === "success"
                ? t("vps.backup.titleDone")
                : t("vps.backup.title", { name: profile.name })}</>}
          description={<>{t("vps.backup.description")}</>}
          closeDisabled={busy || step === "exporting"}>

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
                    <Rich id="vps.backup.warning" tags={{ strong: (content) => <strong>{content}</strong> }} />
                  </p>
                </div>
                <div className="uninstall-target">
                  <GlobeHemisphereWest size={16} />
                  <code>{profile.endpoint.host}</code>
                </div>
                {!disconnected ? (
                  <InlineError message={t("vps.common.disconnectFirst")} />
                ) : null}
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
                  <Field label={t("vps.backup.repeatPassword")} error={backupPasswordConfirmation && backupPasswordConfirmation !== backupPassword ? t("common.error.passwordsDiffer") : undefined}>
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
                  {busy ? t("vps.common.checking") : t("vps.backup.create")}
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
                {t("common.action.back")}
              </button>
              <SshHostVerification
                inspection={trust.inspection}
                confirmed={confirmed}
                onConfirmed={setConfirmed}
              />
              {!disconnected ? (
                <InlineError message={t("vps.common.disconnectFirst")} />
              ) : null}
              <button
                className="primary-button"
                disabled={!confirmed || !valid || busy}
                onClick={() => void exportBackup()}
              >
                <DownloadSimple size={18} /> {t("vps.backup.create")}
              </button>
            </div>
          ) : null}

          {step === "exporting" ? (
            <div className="uninstall-progress repair-progress">
              <ArrowClockwise className="spin" size={26} />
              <strong>{t("vps.backup.progress")}</strong>
              <p>{t("vps.common.keepOpen")}</p>
            </div>
          ) : null}

          {step === "success" && result ? (
            <div className="backup-success repair-success">
              <span>
                <Check size={26} weight="bold" />
              </span>
              <h3>{t("vps.backup.done")}</h3>
              <ShareEncryptedFile uri={path} />
              <p>{t("vps.backup.doneNote")}</p>
              <code>{result.artifact_sha256}</code>
              <button
                className="primary-button"
                onClick={() => changeOpen(false)}
              >
                {t("common.action.done")}
              </button>
            </div>
          ) : null}
        </DialogContent>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
