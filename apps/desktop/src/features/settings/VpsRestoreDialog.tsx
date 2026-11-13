import { SecretInput } from "../../components/SecretInput";
import { useSshOperation } from "../../hooks/useSshOperation";
import { SshLoginFields } from "./SshLoginFields";
import { ServerNetworkPreflight } from "./ServerNetworkPreflight";
import { DialogBack, DialogContent } from "../../components/DialogContent";
import { HashValue } from "../../components/CopyValue";
import { Busy, OperationProgress, OperationResult, stepsAt } from "../../components/OperationResult";
import * as Dialog from "@radix-ui/react-dialog";
import { open } from "../../lib/nativeDialog";
import { Warning } from "@phosphor-icons/react";
import { useId, useState } from "react";
import { api } from "../../api";
import type { InspectedSshHost } from "../../hooks/useSshHostTrust";
import { SshHostVerification } from "./SshHostVerification";
import { validateHost } from "../../format";
import { type ServerProfile, type ServerRestoreResult, type SshCredentials } from "../../types";
import { Field } from "../../components/ui";
import { OperationPlan, ServerChangeFailure } from "../../components/ServerChange";
import { appError, errorMessage } from "../../lib/errors";
import { t } from "../../i18n";
import { Rich } from "../../i18n/Rich";
import { SettingsDisclosure } from "./SettingsParts";

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
  const formId = useId();
  const [host, setHost] = useState(profile.endpoint.host);
  const op = useSshOperation<ServerRestoreResult>(host.trim(), dialogOpen);
  const { login, trust, view: step, busy, phase, result } = op;
  const { port } = login;
  const [path, setPath] = useState("");
  const [backupPassword, setBackupPassword] = useState("");
  const [replaceExisting, setReplaceExisting] = useState(false);
  const [pickerError, setPickerError] = useState<string | null>(null);
  const error = op.error ?? pickerError;

  const reset = () => {
    op.reset();
    setBackupPassword("");
    setHost(profile.endpoint.host);
    setPath("");
    setReplaceExisting(false);
    setPickerError(null);
  };

  // The dialog stays mounted; default to the endpoint saved when it opens.
  const [wasOpen, setWasOpen] = useState(dialogOpen);
  if (wasOpen !== dialogOpen) {
    setWasOpen(dialogOpen);
    if (dialogOpen) setHost(profile.endpoint.host);
  }

  const changeOpen = (next: boolean) => {
    if (!next && busy) return;
    onOpenChange(next);
    if (!next) reset();
  };

  const hostValid = validateHost(host);
  const passwordLong = [...backupPassword].length >= 12;
  const valid =
    disconnected &&
    path.length > 0 &&
    passwordLong &&
    hostValid &&
    login.valid;
  const blocker = !disconnected ? t("vps.common.disconnectFirst")
    : !path ? t("vps.restore.missing.file")
    : !passwordLong ? t("vps.restore.missing.password")
    : !hostValid ? t("vps.restore.missing.host")
    : login.missing ?? (step === "confirmHost" && !trust.confirmed ? t("ssh.verify.confirmFirst") : null);

  const chooseSource = async () => {
    try {
      const selected = await open({
        purpose: "vps_backup_restore",
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
        setPickerError(null);
      }
    } catch (reason) {
      setPickerError(errorMessage(reason, t("vps.common.error.picker")));
    }
  };

  const inspect = async () => {
    if (!valid) return;
    setPickerError(null);
    await op.verify(t("vps.common.error.unreachable"), op.review);
  };

  const restoreInput = (credentials: SshCredentials) => ({
    server_id: profile.id,
    path,
    backup_password: backupPassword,
    host: host.trim(),
    ...credentials,
    replace_existing: replaceExisting,
    confirmed: true,
  });

  const restore = async (checked: InspectedSshHost | null = trust.inspection) => {
    if (!checked || !valid || (checked.status !== "trusted" && !trust.confirmed)) return;
    await op.run(async (credentials, setPhase) => {
      const completed = await api.restoreVpsBackup(restoreInput(credentials));
      setBackupPassword("");
      setPhase(2);
      await onCompleted();
      return completed;
    }, t("vps.restore.error"), {
      inspection: checked,
      // Keep what was entered, except a backup password the file just rejected.
      onError: reason => { if (appError(reason, ["backup_wrong_password"]).code === "backup_wrong_password") setBackupPassword(""); },
    });
  };

  const fileName = path.split(/[\\/]/).pop() ?? path;

  return (
    <Dialog.Root open={dialogOpen} onOpenChange={changeOpen}>
      <Dialog.Portal>
        <Dialog.Overlay className="dialog-overlay" />
        <DialogContent className="dialog-content remove-server-dialog repair-server-dialog vps-restore-dialog"
          heading={t("vps.restore.title", { name: profile.name })}
          data-operation="restore" data-flow-state={op.state.kind}
          description={step === "succeeded" ? t("vps.restore.titleDone") : t("vps.restore.description")}
          closeDisabled={busy}
          footerNote={step === "form" || step === "confirmHost" ? busy ? null : blocker : null}
          footer={step === "running" ? null
            : step === "succeeded" ? <button className="primary-button" type="button" onClick={() => changeOpen(false)}>{t("common.action.done")}</button>
            : <>
              {step !== "form" && <DialogBack disabled={busy} onClick={op.back} />}
              <button className="secondary-button" type="button" disabled={busy} onClick={() => changeOpen(false)}>{t("common.action.cancel")}</button>
              {step === "form" && <button className="primary-button" type="submit" form={formId} disabled={!valid || busy}>{busy ? <Busy label={t("vps.common.checking")} /> : t("vps.restore.review")}</button>}
              {step === "confirmHost" && <button className="primary-button" type="button" disabled={!trust.confirmed || !valid || busy} onClick={op.review}>{t("vps.restore.review")}</button>}
              {step === "review" && <button className="primary-button danger-action" type="button" disabled={!valid || busy} onClick={() => void restore()}>{t("vps.restore.action")}</button>}
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
              <ServerChangeFailure reason={op.failure} message={error} onResolved={() => void onCompleted()} />
              <fieldset disabled={busy} className="ssh-operation-fields">
                <div className="sensitive-backup-warning">
                  <Warning size={19} weight="fill" />
                  <p>
                    <Rich id="vps.restore.warning" tags={{ strong: (content) => <strong>{content}</strong> }} />
                  </p>
                </div>
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
                  <SecretInput field="backup_password"
                    type="password"
                    value={backupPassword}
                    onChange={(event) => setBackupPassword(event.target.value)}
                    autoComplete="off"
                  />
                </Field>
                <Field
                  label={t("vps.restore.host")}
                  hint={t("vps.restore.hostHint")}
                  error={host.trim() && !hostValid ? t("vps.restore.missing.host") : undefined}
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

          {/* What the restore replaces, said once more before the only button that changes the VPS. */}
          {step === "review" ? (
            <section className="restore-review" aria-labelledby="restore-review-heading">
              <h3 id="restore-review-heading">{t("vps.restore.reviewTitle")}</h3>
              <dl className="result-facts">
                <div><dt>{t("vps.restore.file")}</dt><dd className="mono">{fileName}</dd></div>
                <div><dt>{t("vps.restore.host")}</dt><dd className="mono">{`${host.trim()}:${port}`}</dd></div>
              </dl>
              <div className="danger-note">
                <Warning size={18} weight="fill" />
                <ul>
                  <li>{replaceExisting ? t("vps.restore.consequence.replace") : t("vps.restore.consequence.install")}</li>
                  <li>{t("vps.restore.consequence.access")}</li>
                  <li>{t("vps.restore.consequence.device", { host: host.trim() })}</li>
                </ul>
              </div>
            </section>
          ) : null}

          {step === "review" ? <OperationPlan load={() => op.plan((credentials) => ({ operation: "restore", ...restoreInput(credentials) }))} /> : null}

          {step === "running" ? <OperationProgress title={t("vps.restore.progress")}
            steps={stepsAt([t("vps.common.step.identity"), t("vps.restore.step"), t("vps.common.step.refresh")], phase)} /> : null}

          {result ? (
            <OperationResult title={t("vps.restore.done")}>
              <p>{t("vps.restore.doneNote", { host: result.profile.endpoint.host })}</p>
              {(onReviewAccess || onMoveDevices) && <div className="operation-result-actions">
                {onReviewAccess && <button type="button" className="secondary-button" onClick={() => { changeOpen(false); onReviewAccess(); }}>{t("vps.restore.reviewAccess")}</button>}
                {onMoveDevices && <button type="button" className="secondary-button" onClick={() => { changeOpen(false); onMoveDevices(); }}>{t("vps.restore.moveDevices")}</button>}
              </div>}
              {result.network_preflight && <ServerNetworkPreflight report={result.network_preflight} />}
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
