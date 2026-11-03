import { useReleaseUpdateSession } from "./ReleaseUpdateSession";
import { DialogContent } from "../../components/DialogContent";
import { ConfirmationRow } from "../../components/ConfirmationRow";
import { HashValue } from "../../components/CopyValue";
import { Busy, OperationProgress, OperationResult } from "../../components/OperationResult";
import * as Dialog from "@radix-ui/react-dialog";
import {
  DownloadSimple,
  GlobeHemisphereWest,
  LockKey,
  ShieldCheck,
  Warning,
} from "@phosphor-icons/react";
import { useEffect, useId, useState } from "react";
import { api } from "../../api";
import { formatBytes } from "../../format";
import { Field, InlineError } from "../../components/ui";
import { errorMessage } from "../../lib/errors";
import { ReleaseRecovery } from "./ReleaseRecovery";
import { validReleaseSource } from "./vpsRelease";
import { t } from "../../i18n";

export function ReleaseUpdateDialog({
  open,
  onOpenChange,
  installationReady,
  onReviewPrerequisites,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  installationReady: boolean;
  onReviewPrerequisites?: () => void;
}) {
  const formId = useId();
  const { source, setSource, channel, setChannel, candidate, setCandidate, installed, setInstalled } = useReleaseUpdateSession();
  const [confirmed, setConfirmed] = useState(false);
  const [busy, setBusy] = useState<"checking" | "installing" | "disconnecting" | null>(null);
  const [error, setError] = useState<{ message: string; retry?: () => void } | null>(null);
  const [recoveryBusy, setRecoveryBusy] = useState(false);
  const android = candidate?.installer_kind === "android";
  const windows = candidate?.installer_kind === "windows";
  const appimage = candidate?.installer_kind === "appimage";
  const binding = Boolean(candidate?.baseline_bind_available);
  const ready = android || windows || appimage || binding || installationReady;
  const nativeAvailable = Boolean(candidate && (candidate.debian_install_available || candidate.windows_install_available
    || candidate.appimage_install_available || candidate.android_install_available));
  const installConfirmation = android ? t("release.candidate.confirmAndroid") : windows ? t("release.candidate.confirmWindows")
    : appimage ? t("release.candidate.confirmAppImage") : t("release.candidate.confirmDebian");
  const releaseSource = source.trim();
  const sourceValid = validReleaseSource(releaseSource);

  useEffect(() => {
    if (!ready) setConfirmed(false);
  }, [ready]);

  const reset = () => {
    setSource("");
    setChannel("stable");
    setCandidate(null);
    setConfirmed(false);
    setBusy(null);
    setInstalled(false);
    setError(null);
  };

  const changeOpen = (next: boolean) => {
    if (!next && (busy || recoveryBusy)) return;
    if (!next && installed) {
      if(android && !candidate?.baseline_bound) {reset();onOpenChange(false);return;}
      void discard(); return;
    }
    if (!next) setConfirmed(false);
    onOpenChange(next);
  };

  const discard = async () => {
    try { await api.discardReleaseUpdate(); reset(); onOpenChange(false); }
    catch (reason) { setError({ message: errorMessage(reason, t("release.error.discard")), retry: () => void discard() }); }
  };

  const check = async () => {
    if (!sourceValid || busy || recoveryBusy) return;
    setBusy("checking");
    setCandidate(null);
    setConfirmed(false);
    setInstalled(false);
    setError(null);
    try {
      setCandidate(await api.checkReleaseUpdate(releaseSource, channel));
    } catch (reason) {
      setError({ message: errorMessage(reason, t("release.error.check")), retry: () => void check() });
    } finally {
      setBusy(null);
    }
  };

  // After the installed version is verified, the next step is always a check for a newer release.
  const checkAfterBinding = async () => {
    try { await api.discardReleaseUpdate(); }
    catch (reason) { setError({ message: errorMessage(reason, t("release.error.discard")), retry: () => void checkAfterBinding() }); return; }
    await check();
  };

  const install = async () => {
    if (!candidate || !confirmed || !ready || busy) return;
    setBusy("installing");
    setError(null);
    try {
      setCandidate(await (android && binding ? api.installReleaseUpdate(true, true) : api.installReleaseUpdate(true)));
      setInstalled(true);
      setConfirmed(false);
    } catch (reason) {
      setConfirmed(false);
      setError({ message: errorMessage(
        reason,
        windows ? t("release.error.installWindows")
          : appimage ? t("release.error.installAppImage")
          : t("release.error.installDebian"),
      ) });
    } finally {
      setBusy(null);
    }
  };

  // Fixes the readiness blocker here, so the reviewed release stays on screen.
  const disconnect = async () => {
    setBusy("disconnecting");
    setError(null);
    try { await api.disconnect(); }
    catch (reason) { setError({ message: errorMessage(reason, t("maintenance.review.disconnectFailed")), retry: () => void disconnect() }); }
    finally { setBusy(null); }
  };

  const installable = Boolean((candidate?.newer_than_running || binding) && nativeAvailable);
  const installAvailable = installable && ready;
  const failure = error ? <InlineError message={error.message} onRetry={error.retry} retryDisabled={Boolean(busy)} /> : null;

  const footer = installed && candidate
    ? candidate.baseline_bound
      ? <>
          <button className="secondary-button" type="button" onClick={() => changeOpen(false)}>{t("common.action.close")}</button>
          <button className="primary-button" type="button" disabled={Boolean(busy)} onClick={() => void checkAfterBinding()}>
            {busy === "checking" ? <Busy label={t("release.form.checking")} /> : t("release.done.checkNewer")}
          </button>
        </>
      : <button className="primary-button" type="button" onClick={() => changeOpen(false)}>
          {android || windows ? t("common.action.close") : t("release.done.closeLater")}
        </button>
    : busy === "installing" ? null
    : candidate
      ? <>
          <button className="secondary-button" type="button" disabled={Boolean(busy)} onClick={() => void discard()}>{t("release.candidate.discard")}</button>
          {installable && <button className="primary-button" type="button" disabled={!confirmed || !installAvailable || Boolean(busy)} onClick={() => void install()}>
            <ShieldCheck size={18} /> {binding ? t("release.candidate.verify") : t("release.candidate.install")}
          </button>}
        </>
      : <button className="primary-button release-check-button" type="submit" form={formId} disabled={!sourceValid || Boolean(busy) || recoveryBusy}>
          {busy === "checking" ? <Busy label={t("release.form.checking")} /> : <><ShieldCheck size={18} />{t("release.form.check")}</>}
        </button>;
  const footerNote = busy || installed ? null
    : candidate ? installable ? !ready ? t("release.candidate.readyFirst") : !confirmed ? t("release.candidate.confirmFirst") : null : null
    : sourceValid ? null : t("release.form.sourceFirst");

  return (
    <Dialog.Root open={open} onOpenChange={changeOpen}>
      <Dialog.Portal>
        <Dialog.Overlay className="dialog-overlay" />
        <DialogContent className="dialog-content release-update-dialog"
          heading={t("release.dialog.title")}
          description={installed && candidate ? candidate.baseline_bound ? t("release.done.titleVerified") : android ? t("release.done.titleAndroid")
            : windows ? t("release.done.titleWindows") : t("release.done.titleInstalled") : t("release.dialog.description")}
          closeDisabled={Boolean(busy) || recoveryBusy} closeLabel={t("release.dialog.close")}
          footerNote={footerNote}
          footer={footer}>

          {installed && candidate ? (
            <OperationResult title={candidate.baseline_bound ? t("release.done.headingVerified", { version: candidate.release_version })
                : windows ? t("release.done.headingWindows", { version: candidate.release_version })
                : t("release.done.headingInstalled", { version: candidate.release_version })}>
              <p>
                {candidate.baseline_bound ? t("release.done.bodyVerified")
                  : android ? t("release.done.bodyAndroid") : windows ? t("release.done.bodyWindows")
                  : appimage ? t("release.done.bodyAppImage")
                  : t("release.done.bodyDebian")}
              </p>
              {failure}
            </OperationResult>
          ) : busy === "installing" ? (
            <OperationProgress
              title={binding ? t("release.progress.verifying") : t("release.progress.installing")}
              note={binding ? t("release.progress.verifyingBody")
                : android ? t("release.progress.android") : appimage ? t("release.progress.appImage")
                : windows ? t("release.progress.windows") : t("release.progress.debian")} />
          ) : candidate ? (
            <div className="release-candidate">
              {failure}
              <div className="release-candidate-heading">
                <span className="release-authenticated">
                  <ShieldCheck size={16} weight="fill" /> {t("release.candidate.verified")}
                </span>
                {candidate.security_update ? (
                  <span className="release-security-label">
                    {t("release.candidate.security")}
                  </span>
                ) : null}
                <h3>{t("release.candidate.title", { version: candidate.release_version })}</h3>
                <p>
                  {t("release.candidate.meta", {
                    channel: candidate.channel === "preview" ? t("release.channel.preview") : t("release.channel.stable"),
                    current: candidate.current_version,
                  })}
                </p>
                {candidate.channel === "preview" && <p className="release-preview-note">{t("release.form.previewHint")}</p>}
              </div>
              <p>{t("release.candidate.package", { size: formatBytes(candidate.artifact_size_bytes) })}</p>
              <p className="settings-note">{t("release.candidate.source", { source })}</p>

              {binding ? <p className="settings-note">{t("release.candidate.verifyOnce")}</p> : !candidate.newer_than_running ? (
                <div className="warning-note replacement-warning">
                  <Warning size={18} weight="fill" />
                  <span>{t("release.candidate.notNewer")}</span>
                </div>
              ) : !nativeAvailable ? (
                <div className="warning-note replacement-warning">
                  <Warning size={18} weight="fill" />
                  <span>
                    {windows ? t("release.candidate.notInstallableWindows") : t("release.candidate.notInstallableLinux")}
                  </span>
                </div>
              ) : null}

              {/* Readiness is the one blocker the user can fix here (controls stay, disabled); a release that can never be installed offers none. */}
              {!ready && installable && <div className="update-blocker">
                <Warning size={20} weight="fill" />
                <div>
                  <p>{t("release.candidate.notReady")}</p>
                  <div className="update-blocker-actions">
                    <button type="button" className="secondary-button" disabled={Boolean(busy)} onClick={() => void disconnect()}>
                      {busy === "disconnecting" ? <Busy label={t("maintenance.review.disconnecting")} /> : t("maintenance.review.disconnect")}
                    </button>
                    <button type="button" className="text-button" onClick={() => { changeOpen(false); onReviewPrerequisites?.(); }}>{t("release.candidate.openConnection")}</button>
                  </div>
                </div>
              </div>}
              {installable && <ConfirmationRow checked={confirmed} disabled={!installAvailable} onChange={setConfirmed}>
                <strong>{binding ? t("release.candidate.confirmVerify") : installConfirmation}</strong>
                <small>{t("release.candidate.confirmNote")}</small>
              </ConfirmationRow>}
              <details className="release-verification-details"><summary>{t("release.candidate.details")}</summary>
                <dl className="result-facts">
                  <div><dt>{t("release.candidate.detailPackage")}</dt><dd className="mono">{candidate.artifact_file_name}</dd></div>
                  <div><dt>{t("release.candidate.detailSize")}</dt><dd>{formatBytes(candidate.artifact_size_bytes)}</dd></div>
                  <div><dt>{t("release.candidate.detailTarget")}</dt><dd className="mono">{candidate.artifact_target}</dd></div>
                  <div><dt>{t("release.candidate.detailRelease")}</dt><dd>{candidate.release_sequence}</dd></div>
                  <div><dt>{t("release.candidate.detailPolicy")}</dt><dd>{t("release.candidate.detailPolicyValue", { sequence: candidate.trust_policy_sequence })}</dd></div>
                </dl>
                <HashValue label={t("release.candidate.digest")} value={candidate.artifact_sha256} />
                <HashValue label={t("release.candidate.detailRoot")} value={candidate.root_key_id_sha256} />
                <HashValue label={t("release.candidate.detailSigner")} value={candidate.release_key_id_sha256} />
              </details>
              <p className="form-footnote">
                <LockKey size={15} /> {t("release.candidate.footnote")}
              </p>
            </div>
          ) : (
            <form className="release-update-form" id={formId} onSubmit={(event) => { event.preventDefault(); void check(); }}>
              {failure}
              <div className="segmented-control release-channel-tabs" role="group" aria-label={t("release.form.channel")}>
                <button
                  type="button"
                  aria-pressed={channel === "stable"}
                  disabled={Boolean(busy)}
                  onClick={() => setChannel("stable")}
                >
                  {t("release.form.stable")}
                </button>
                <button
                  type="button"
                  aria-pressed={channel === "preview"}
                  disabled={Boolean(busy)}
                  onClick={() => setChannel("preview")}
                >
                  {t("release.form.preview")}
                </button>
              </div>
              {channel === "preview" && <p className="release-preview-note">{t("release.form.previewHint")}</p>}
              <Field
                label={t("release.form.source")}
                hint={t("release.form.sourceHint")}
                error={releaseSource && !sourceValid ? t("vps.update.source.invalid") : undefined}
              >
                <input
                  type="url"
                  value={source}
                  onChange={(event) => setSource(event.target.value)}
                  autoComplete="off"
                  autoCapitalize="none"
                  autoCorrect="off"
                  spellCheck={false}
                  disabled={Boolean(busy)}
                  required
                />
              </Field>
              <div className="release-download-notice">
                <DownloadSimple size={20} />
                <p>
                  <strong>{t("release.form.noticeTitle")}</strong>
                  <span>{t("release.form.noticeBody")}</span>
                </p>
              </div>
              <p className="form-footnote">
                <GlobeHemisphereWest size={15} /> {t("release.form.privacy")}
              </p>
              <ReleaseRecovery busy={Boolean(busy) || recoveryBusy} setBusy={setRecoveryBusy} />
            </form>
          )}
        </DialogContent>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
