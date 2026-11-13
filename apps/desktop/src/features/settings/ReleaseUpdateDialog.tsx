import { useReleaseUpdateSession } from "./ReleaseUpdateSession";
import { disconnectTunnel } from "../connection/connectionCommands";
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
import { useEffect, useId } from "react";
import { api } from "../../api";
import { formatBytes, formatTarget } from "../../format";
import { Field, InlineError } from "../../components/ui";
import { errorMessage } from "../../lib/errors";
import { ReleaseRecovery } from "./ReleaseRecovery";
import { completeReleaseSource, rememberAppReleaseSource, rememberedAppReleaseSource, validReleaseSource } from "./vpsRelease";
import { SettingsDisclosure } from "./SettingsParts";
import { notify } from "../../components/Toasts";
import { releaseBusy } from "./releaseUpdateMachine";
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
  const { source, setSource, channel, setChannel, state, dispatch } = useReleaseUpdateSession();
  const candidate = state.kind === "reviewing" || state.kind === "installing" || state.kind === "installed" ? state.candidate : null;
  const installed = state.kind === "installed" ? state : null;
  const confirmed = state.kind === "reviewing" && state.confirmed;
  // Legacy names for the one running step, read by the markup below.
  const busy = state.kind === "checking" ? "checking" : state.kind === "installing" ? "installing"
    : state.kind === "form" && state.busy === "recovering" ? null : "busy" in state ? state.busy : null;
  const restored = state.kind === "form" && state.restored;
  const locked = releaseBusy(state);
  const android = candidate?.installer_kind === "android";
  const windows = candidate?.installer_kind === "windows";
  const appimage = candidate?.installer_kind === "appimage";
  // pacman (the AUR packages) owns the files: show the version, leave installing it to pacman.
  const packageManager = candidate?.installer_kind === "package_manager";
  const binding = Boolean(candidate?.baseline_bind_available);
  const ready = android || windows || appimage || binding || installationReady;
  const nativeAvailable = Boolean(candidate && (candidate.debian_install_available || candidate.windows_install_available
    || candidate.appimage_install_available || candidate.android_install_available));
  const installConfirmation = android ? t("release.candidate.confirmAndroid") : windows ? t("release.candidate.confirmWindows")
    : appimage ? t("release.candidate.confirmAppImage") : t("release.candidate.confirmDebian");
  const releaseSource = completeReleaseSource(source);
  const sourceValid = validReleaseSource(releaseSource);

  useEffect(() => {
    if (!ready) dispatch({ type: "confirm", value: false });
  }, [ready, dispatch]);

  const reset = () => {
    // Back to the remembered address, not an empty field: discarding a download isn't forgetting the source.
    setSource(rememberedAppReleaseSource());
    setChannel("stable");
    dispatch({ type: "reset" });
  };

  const changeOpen = (next: boolean) => {
    if (!next && locked) return;
    if (!next && installed) {
      // Android keeps its install pending until the system installer finishes or the user cancels it.
      const keepPending = android && installed.restart !== "bound";
      reset();
      onOpenChange(false);
      // The dialog closes either way; a failed discard only leaves the downloaded file for the next check to replace.
      if (!keepPending) void api.discardReleaseUpdate().catch((reason) => notify(errorMessage(reason, t("release.error.discard")), "error"));
      return;
    }
    if (!next) dispatch({ type: "closed" });
    onOpenChange(next);
  };

  const discard = async () => {
    dispatch({ type: "discard" });
    try { await api.discardReleaseUpdate(); reset(); }
    catch (reason) { dispatch({ type: "discardFailed", error: { message: errorMessage(reason, t("release.error.discard")), retry: "discard" } }); }
  };

  const check = async () => {
    if (!sourceValid || locked) return;
    dispatch({ type: "check" });
    try {
      dispatch({ type: "checked", candidate: await api.checkReleaseUpdate(releaseSource, channel) });
      // Only an address that served a signed release is worth offering next time.
      rememberAppReleaseSource(releaseSource);
    } catch (reason) {
      // The footer's Check release button is the retry.
      dispatch({ type: "checkFailed", message: errorMessage(reason, t("release.error.check")) });
    }
  };

  // After the installed version is verified, the next step is always a check for a newer release.
  const checkAfterBinding = async () => {
    dispatch({ type: "checkAfterBinding" });
    try { await api.discardReleaseUpdate(); }
    catch (reason) { dispatch({ type: "discardFailed", error: { message: errorMessage(reason, t("release.error.discard")), retry: "checkAfterBinding" } }); return; }
    dispatch({ type: "check" });
    try {
      dispatch({ type: "checked", candidate: await api.checkReleaseUpdate(releaseSource, channel) });
    } catch (reason) {
      dispatch({ type: "checkFailed", message: errorMessage(reason, t("release.error.check")) });
    }
  };

  const install = async () => {
    if (!candidate || !confirmed || !ready || locked) return;
    dispatch({ type: "install" });
    try {
      dispatch({ type: "installed", candidate: await (android && binding ? api.installReleaseUpdate(true, true) : api.installReleaseUpdate(true)) });
    } catch (reason) {
      dispatch({ type: "installFailed", message: errorMessage(
        reason,
        binding ? t("release.error.bind")
          : windows ? t("release.error.installWindows")
          : appimage ? t("release.error.installAppImage")
          : t("release.error.installDebian"),
      ) });
    }
  };

  // Fixes the readiness blocker here, so the reviewed release stays on screen.
  const disconnect = async () => {
    dispatch({ type: "disconnect" });
    try { await disconnectTunnel(null); dispatch({ type: "disconnected" }); }
    catch (reason) { dispatch({ type: "disconnected", error: { message: errorMessage(reason, t("maintenance.review.disconnectFailed")), retry: "disconnect" } }); }
  };

  // The VPN runs in its own service, so only the window restarts. On success the app exits and stays busy until then.
  const restart = async () => {
    dispatch({ type: "restart" });
    try { await api.restartApp(); }
    catch { dispatch({ type: "restartFailed", message: t("release.done.restartFailed") }); }
  };

  const retries = { discard, checkAfterBinding, disconnect };
  const error = "error" in state ? state.error : null;
  const installable = Boolean((candidate?.newer_than_running || binding) && nativeAvailable);
  const installAvailable = installable && ready;
  const failure = error ? <InlineError message={error.message} onRetry={error.retry && (() => void retries[error.retry!]())} retryDisabled={locked} /> : null;

  const footer = installed && candidate
    ? installed.restart === "bound"
      ? <>
          <button className="secondary-button" type="button" disabled={locked} onClick={() => changeOpen(false)}>{t("common.action.close")}</button>
          <button className="primary-button" type="button" disabled={locked} onClick={() => void checkAfterBinding()}>
            {busy === "checking" ? <Busy label={t("release.form.checking")} /> : t("release.done.checkNewer")}
          </button>
        </>
      : installed.restart === "external"
        ? <button className="primary-button" type="button" onClick={() => changeOpen(false)}>{t("common.action.close")}</button>
        : <>
            <button className="secondary-button" type="button" disabled={locked} onClick={() => changeOpen(false)}>{t("release.done.closeLater")}</button>
            <button className="primary-button" type="button" disabled={locked} onClick={() => void restart()}>
              {busy === "restarting" ? <Busy label={t("release.done.restarting")} /> : t("release.done.restartNow")}
            </button>
          </>
    : state.kind === "installing" ? null
    : candidate
      ? <>
          <button className="secondary-button" type="button" disabled={locked} onClick={() => void discard()}>{t("release.candidate.discard")}</button>
          {installable && <button className="primary-button" type="button" disabled={!confirmed || !installAvailable || locked} onClick={() => void install()}>
            <ShieldCheck size={18} /> {binding ? t("release.candidate.verify") : t("release.candidate.install")}
          </button>}
        </>
      : <button className="primary-button release-check-button" type="submit" form={formId} disabled={!sourceValid || locked}>
          {busy === "checking" ? <Busy label={t("release.form.checking")} /> : <><ShieldCheck size={18} />{t("release.form.check")}</>}
        </button>;
  const footerNote = locked || installed || restored ? null
    : candidate ? installable ? !ready ? t("release.candidate.readyFirst") : !confirmed ? t("release.candidate.confirmFirst") : null : null
    : releaseSource ? null : t("release.form.sourceFirst");

  return (
    <Dialog.Root open={open} onOpenChange={changeOpen}>
      <Dialog.Portal>
        <Dialog.Overlay className="dialog-overlay" />
        <DialogContent className="dialog-content release-update-dialog"
          heading={t("release.dialog.title")}
          description={installed && candidate ? installed.restart === "bound" ? t("release.done.titleVerified") : android ? t("release.done.titleAndroid")
            : windows ? t("release.done.titleWindows") : t("release.done.titleInstalled") : t("release.dialog.description")}
          data-flow-state={state.kind} closeDisabled={locked} closeLabel={t("release.dialog.close")}
          footerNote={footerNote}
          footer={footer}>

          {installed && candidate ? (
            <OperationResult title={installed.restart === "bound" ? t("release.done.headingVerified", { version: candidate.release_version })
                : windows ? t("release.done.headingWindows", { version: candidate.release_version })
                : t("release.done.headingInstalled", { version: candidate.release_version })}>
              <p>
                {installed.restart === "bound" ? t("release.done.bodyVerified")
                  : android ? t("release.done.bodyAndroid") : windows ? t("release.done.bodyWindows")
                  : appimage ? t("release.done.bodyAppImage")
                  : t("release.done.bodyDebian")}
              </p>
              {failure}
            </OperationResult>
          ) : state.kind === "installing" ? (
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
                {/* A security label only matters on a release that would be installed. */}
                {candidate.security_update && (candidate.newer_than_running || binding) ? (
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
              {/* Signed notes are plain text; React renders them without markup. */}
              {/* "What's new" only for a release that would be installed; a verify or the current version just has notes. */}
              {candidate.release_notes && <p className="release-notes"><strong>{t(installable && !binding ? "release.candidate.whatsNew" : "release.candidate.notes")}</strong> <span lang="en" dir="auto">{candidate.release_notes}</span></p>}
              <p>{t("release.candidate.package", { size: formatBytes(candidate.artifact_size_bytes) })}</p>
              <p className="settings-note">{t("release.candidate.source", { source })}</p>

              {binding ? <p className="settings-note">{t("release.candidate.verifyOnce")}</p> : !candidate.newer_than_running ? (
                <div className="warning-note replacement-warning">
                  <Warning size={18} weight="fill" />
                  <span>{t("release.candidate.notNewer")}</span>
                </div>
              ) : packageManager ? (
                <p className="settings-note">{t("release.candidate.packageManager", { version: candidate.release_version })}</p>
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
                    <button type="button" className="secondary-button" disabled={locked} onClick={() => void disconnect()}>
                      {busy === "disconnecting" ? <Busy label={t("maintenance.review.disconnecting")} /> : t("maintenance.review.disconnect")}
                    </button>
                    <button type="button" className="text-button" onClick={() => { changeOpen(false); onReviewPrerequisites?.(); }}>{t("release.candidate.openConnection")}</button>
                  </div>
                </div>
              </div>}
              {installable && <ConfirmationRow checked={confirmed} disabled={!installAvailable || locked} onChange={value => dispatch({ type: "confirm", value })}>
                <strong>{binding ? t("release.candidate.confirmVerify") : installConfirmation}</strong>
                <small>{t("release.candidate.confirmNote")}</small>
              </ConfirmationRow>}
              <SettingsDisclosure className="release-verification-details" summary={t("release.candidate.details")}>
                <dl className="result-facts">
                  <div><dt>{t("release.candidate.detailPackage")}</dt><dd className="mono">{candidate.artifact_file_name}</dd></div>
                  <div><dt>{t("release.candidate.detailSize")}</dt><dd>{formatBytes(candidate.artifact_size_bytes)}</dd></div>
                  <div><dt>{t("release.candidate.detailTarget")}</dt><dd>{formatTarget(candidate.artifact_target)}</dd></div>
                  <div><dt>{t("release.candidate.detailRelease")}</dt><dd>{candidate.release_sequence}</dd></div>
                  <div><dt>{t("release.candidate.detailPolicy")}</dt><dd>{t("release.candidate.detailPolicyValue", { sequence: String(candidate.trust_policy_sequence) })}</dd></div>
                </dl>
                <HashValue label={t("release.candidate.digest")} value={candidate.artifact_sha256} />
                <HashValue label={t("release.candidate.detailRoot")} value={candidate.root_key_id_sha256} />
                <HashValue label={t("release.candidate.detailSigner")} value={candidate.release_key_id_sha256} />
              </SettingsDisclosure>
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
                  disabled={locked}
                  onClick={() => setChannel("stable")}
                >
                  {t("release.form.stable")}
                </button>
                <button
                  type="button"
                  aria-pressed={channel === "preview"}
                  disabled={locked}
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
                  onBlur={() => setSource(releaseSource)}
                  autoComplete="off"
                  autoCapitalize="none"
                  autoCorrect="off"
                  spellCheck={false}
                  disabled={locked}
                  required
                />
              </Field>
              <SettingsDisclosure boxed summary={t("release.form.sourceInfoLabel")}><p className="settings-note">{t("release.form.sourceInfo")}</p></SettingsDisclosure>
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
              <ReleaseRecovery busy={locked} setBusy={running => dispatch({ type: "recovery", running })} onRestored={() => dispatch({ type: "recovery", running: false, restored: true })}
                onRestart={() => void restart()} restarting={busy === "restarting"} />
            </form>
          )}
        </DialogContent>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
