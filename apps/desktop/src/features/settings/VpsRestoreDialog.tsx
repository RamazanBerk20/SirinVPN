import { SecretInput } from "../../components/SecretInput";
import { useSshLogin } from "../../hooks/useSshLogin";
import { SshLoginFields } from "./SshLoginFields";
import { ServerNetworkPreflight } from "./ServerNetworkPreflight";
import { DialogContent } from "../../components/DialogContent";
import * as Dialog from "@radix-ui/react-dialog";
import { open } from "../../lib/nativeDialog";
import {
  ArrowClockwise,
  Check,
  UploadSimple,
  Warning,
} from "@phosphor-icons/react";
import { useEffect, useState } from "react";
import { api } from "../../api";
import {
  useSshHostTrust,
  type InspectedSshHost,
} from "../../hooks/useSshHostTrust";
import { SshHostVerification } from "./SshHostVerification";
import { validateHost } from "../../format";
import { type ServerProfile, type ServerRestoreResult } from "../../types";
import { Field, InlineError } from "../../components/ui";
import { errorMessage } from "../../lib/errors";
import { t } from "../../i18n";
import { Rich } from "../../i18n/Rich";

export function VpsRestoreDialog({
  profile,
  open: dialogOpen,
  onOpenChange,
  disconnected,
  onCompleted,
  onReviewAccess,
  onMoveDevices,
}: {
  profile: ServerProfile;
  open: boolean;
  onOpenChange: (open: boolean) => void;
  disconnected: boolean;
  onCompleted: () => Promise<void>;
  onReviewAccess?: () => void;
  onMoveDevices?: () => void;
}) {
  const [step, setStep] = useState<
    "details" | "fingerprint" | "restoring" | "success"
  >("details");
  const [host, setHost] = useState(profile.endpoint.host);
  const login = useSshLogin(host, dialogOpen);
  const { port } = login;
  const [path, setPath] = useState("");
  const [backupPassword, setBackupPassword] = useState("");
  const trust = useSshHostTrust(host.trim(), Number(port), dialogOpen);
  const [replaceExisting, setReplaceExisting] = useState(false);
  const [confirmed, setConfirmed] = useState(false);
  const [result, setResult] = useState<ServerRestoreResult | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const clearSecrets = () => {
    login.clearSecrets();
    setBackupPassword("");
  };

  const reset = () => {
    clearSecrets();
    setStep("details");
    setHost(profile.endpoint.host);
    setPath("");
    trust.reset();
    setReplaceExisting(false);
    setConfirmed(false);
    setResult(null);
    setBusy(false);
    setError(null);
  };

  useEffect(() => {
    // The dialog stays mounted; default to the endpoint saved when it opens.
    if (dialogOpen) setHost(profile.endpoint.host);
  }, [dialogOpen]);

  const changeOpen = (next: boolean) => {
    if (!next && (busy || step === "restoring")) return;
    onOpenChange(next);
    if (!next) reset();
  };

  const valid =
    disconnected &&
    path.length > 0 &&
    [...backupPassword].length >= 12 &&
    validateHost(host) &&
    login.valid;

  const chooseSource = async () => {
    try {
      const selected = await open({
        title: t("vps.restore.openDialogTitle"),
        multiple: false,
        directory: false,
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
        await restore(checked);
      } else {
        setStep("fingerprint");
      }
    } catch (reason) {
      setError(
        errorMessage(reason, t("vps.common.error.unreachable")),
      );
    } finally {
      setBusy(false);
    }
  };

  const restore = async (
    checked: InspectedSshHost | null = trust.inspection,
  ) => {
    if (!checked || !valid || (checked.status !== "trusted" && !confirmed))
      return;
    setStep("restoring");
    setBusy(true);
    setError(null);
    try {
      const fingerprint = await trust.accept(checked, confirmed);
      const completed = await api.restoreVpsBackup({
        server_id: profile.id,
        path,
        backup_password: backupPassword,
        host: host.trim(),
        ...(await login.prepare(fingerprint)),
        replace_existing: replaceExisting,
        confirmed: true,
      });
      clearSecrets();
      setResult(completed);
      await onCompleted();
      setStep("success");
    } catch (reason) {
      clearSecrets();
      setConfirmed(false);
      setStep("details");
      setError(
        errorMessage(reason, t("vps.restore.error")),
      );
    } finally {
      setBusy(false);
    }
  };

  return (
    <Dialog.Root open={dialogOpen} onOpenChange={changeOpen}>
      <Dialog.Portal>
        <Dialog.Overlay className="dialog-overlay" />
        <DialogContent className="dialog-content remove-server-dialog repair-server-dialog vps-restore-dialog"
          heading={<>{step === "restoring"
              ? t("vps.restore.titleRunning")
              : step === "success"
                ? t("vps.restore.titleDone")
                : t("vps.restore.title", { name: profile.name })}</>}
          description={<>{t("vps.restore.description")}</>}
          closeDisabled={busy || step === "restoring"}>

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
                    <Rich id="vps.restore.warning" tags={{ strong: (content) => <strong>{content}</strong> }} />
                  </p>
                </div>
                {!disconnected ? (
                  <InlineError message={t("vps.common.disconnectFirst")} />
                ) : null}
                <Field label={t("vps.restore.file")}>
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
                      onClick={() => void chooseSource()}
                      disabled={busy}
                    >
                      {t("vps.common.chooseFile")}
                    </button>
                  </div>
                </Field>
                <Field label={t("vps.common.backupPassword")}>
                  <SecretInput
                    type="password"
                    value={backupPassword}
                    onChange={(event) => setBackupPassword(event.target.value)}
                    autoComplete="off"
                  />
                </Field>
                <Field
                  label={t("vps.restore.host")}
                  hint={t("vps.restore.hostHint")}
                >
                  <input
                    value={host}
                    onChange={(event) => setHost(event.target.value)}
                    autoCapitalize="none"
                    spellCheck={false}
                  />
                </Field>
                <SshLoginFields login={login} />
                <label
                  className={`replacement-option ${replaceExisting ? "selected" : ""}`}
                >
                  <input
                    type="checkbox"
                    checked={replaceExisting}
                    onChange={(event) =>
                      setReplaceExisting(event.target.checked)
                    }
                  />
                  <span>
                    <strong>{t("vps.restore.replace")}</strong>
                    <small>{t("vps.restore.replaceHint")}</small>
                  </span>
                </label>
                {error ? <InlineError message={error} /> : null}
                <button
                  className="primary-button"
                  type="submit"
                  disabled={!valid || busy}
                >
                  {busy ? t("vps.common.checking") : t("vps.restore.action")}
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
                onClick={() => void restore()}
              >
                <UploadSimple size={18} /> {t("vps.restore.action")}
              </button>
            </div>
          ) : null}

          {step === "restoring" ? (
            <div className="uninstall-progress repair-progress">
              <ArrowClockwise className="spin" size={26} />
              <strong>{t("vps.restore.progress")}</strong>
              <p>{t("vps.common.keepOpen")}</p>
            </div>
          ) : null}

          {step === "success" && result ? (
            <div className="backup-success repair-success">
              <span>
                <Check size={26} weight="bold" />
              </span>
              <h3>{t("vps.restore.done")}</h3>
              <p>{t("vps.restore.doneNote", { host: result.profile.endpoint.host })}</p>
              {onReviewAccess && <button className="secondary-button" onClick={() => { changeOpen(false); onReviewAccess(); }}>{t("vps.restore.reviewAccess")}</button>}
              {onMoveDevices && <button className="secondary-button" onClick={() => { changeOpen(false); onMoveDevices(); }}>{t("vps.restore.moveDevices")}</button>}
              <code>{result.artifact_sha256}</code>
              {result.network_preflight && <ServerNetworkPreflight report={result.network_preflight} />}
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
