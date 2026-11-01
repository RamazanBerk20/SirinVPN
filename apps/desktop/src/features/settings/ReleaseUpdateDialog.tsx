import { useReleaseUpdateSession } from "./ReleaseUpdateSession";
import { DialogContent } from "../../components/DialogContent";
import * as Dialog from "@radix-ui/react-dialog";
import {
  ArrowClockwise,
  Check,
  DownloadSimple,
  GlobeHemisphereWest,
  LockKey,
  ShieldCheck,
  Warning,
} from "@phosphor-icons/react";
import { useEffect, useState } from "react";
import { api } from "../../api";
import { formatBytes } from "../../format";
import { Field, InlineError } from "../../components/ui";
import { errorMessage } from "../../lib/errors";
import { ReleaseRecovery } from "./ReleaseRecovery";
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
  const { source, setSource, channel, setChannel, candidate, setCandidate, installed, setInstalled } = useReleaseUpdateSession();
  const [confirmed, setConfirmed] = useState(false);
  const [busy, setBusy] = useState<"checking" | "installing" | null>(null);
  const [error, setError] = useState<string | null>(null);
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
    catch (reason) { setError(errorMessage(reason, t("release.error.discard"))); }
  };

  const check = async (event: React.FormEvent) => {
    event.preventDefault();
    const releaseSource = source.trim();
    if (!releaseSource || busy || recoveryBusy) return;
    setBusy("checking");
    setCandidate(null);
    setConfirmed(false);
    setInstalled(false);
    setError(null);
    try {
      setCandidate(await api.checkReleaseUpdate(releaseSource, channel));
    } catch (reason) {
      setError(errorMessage(reason, t("release.error.check")));
    } finally {
      setBusy(null);
    }
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
      setError(
        errorMessage(
          reason,
          windows ? t("release.error.installWindows")
            : appimage ? t("release.error.installAppImage")
            : t("release.error.installDebian"),
        ),
      );
    } finally {
      setBusy(null);
    }
  };

  const installable = Boolean((candidate?.newer_than_running || binding) && nativeAvailable);
  const installAvailable = Boolean(
    (candidate?.newer_than_running || binding) &&
    nativeAvailable &&
    ready,
  );

  return (
    <Dialog.Root open={open} onOpenChange={changeOpen}>
      <Dialog.Portal>
        <Dialog.Overlay className="dialog-overlay" />
        <DialogContent className="dialog-content release-update-dialog"
          heading={installed ? candidate?.baseline_bound ? t("release.done.titleVerified") : android ? t("release.done.titleAndroid")
            : windows ? t("release.done.titleWindows") : t("release.done.titleInstalled") : t("release.dialog.title")}
          description={t("release.dialog.description")}
          closeDisabled={Boolean(busy) || recoveryBusy} closeLabel={t("release.dialog.close")}>

          {installed && candidate ? (
            <div className="backup-success release-update-success">
              <span>
                <Check size={26} weight="bold" />
              </span>
              <h3>{candidate.baseline_bound ? t("release.done.headingVerified", { version: candidate.release_version })
                : windows ? t("release.done.headingWindows", { version: candidate.release_version })
                : t("release.done.headingInstalled", { version: candidate.release_version })}</h3>
              <p>
                {candidate.baseline_bound ? t("release.done.bodyVerified")
                  : android ? t("release.done.bodyAndroid") : windows ? t("release.done.bodyWindows")
                  : appimage ? t("release.done.bodyAppImage")
                  : t("release.done.bodyDebian")}
              </p>
              <button
                className="primary-button"
                type="button"
                onClick={() => changeOpen(false)}
              >
                {android || windows || candidate.baseline_bound ? t("common.action.close") : t("release.done.closeLater")}
              </button>
            </div>
          ) : busy === "installing" ? (
            <div className="uninstall-progress release-update-progress">
              <ArrowClockwise className="spin" size={27} />
              <strong>{binding ? t("release.progress.verifying") : t("release.progress.installing")}</strong>
              <p>
                {binding ? t("release.progress.verifyingBody")
                  : android ? t("release.progress.android") : appimage ? t("release.progress.appImage")
                  : windows ? t("release.progress.windows") : t("release.progress.debian")}
              </p>
            </div>
          ) : candidate ? (
            <div className="release-candidate">
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
                    sequence: candidate.release_sequence,
                  })}
                </p>
              </div>
              <p>{t("release.candidate.package", { size: formatBytes(candidate.artifact_size_bytes) })}</p>
              <p className="settings-note">{t("release.candidate.source", { source })}</p>
              <details className="release-verification-details"><summary>{t("release.candidate.details")}</summary>
              <div className="release-detail-grid">
                <div>
                  <span>{t("release.candidate.detailPackage")}</span>
                  <strong>{candidate.artifact_file_name}</strong>
                </div>
                <div>
                  <span>{t("release.candidate.detailSize")}</span>
                  <strong>{formatBytes(candidate.artifact_size_bytes)}</strong>
                </div>
                <div>
                  <span>{t("release.candidate.detailTarget")}</span>
                  <strong>{candidate.artifact_target}</strong>
                </div>
                <div>
                  <span>{t("release.candidate.detailPolicy")}</span>
                  <strong>{t("release.candidate.detailPolicyValue", { sequence: candidate.trust_policy_sequence })}</strong>
                </div>
                <div>
                  <span>{t("release.candidate.detailRoot")}</span>
                  <code title={candidate.root_key_id_sha256}>
                    {candidate.root_key_id_sha256}
                  </code>
                </div>
                <div>
                  <span>{t("release.candidate.detailSigner")}</span>
                  <code title={candidate.release_key_id_sha256}>
                    {candidate.release_key_id_sha256}
                  </code>
                </div>
              </div>
              <div className="release-digest">
                <span>{t("release.candidate.digest")}</span>
                <code>{candidate.artifact_sha256}</code>
              </div>

              </details>

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
              ) : !ready ? (
                <div className="warning-note replacement-warning">
                  <Warning size={18} weight="fill" />
                  <span>{t("release.candidate.notReady")}</span>
                </div>
              ) : null}

              {/* Readiness is the one blocker the user can fix here (controls stay, disabled); a release that can never be installed offers none. */}
              {!ready && installable && <button className="secondary-button" onClick={() => { changeOpen(false); onReviewPrerequisites?.(); }}>{t("release.candidate.openConnection")}</button>}
              {installable && <label
                className={`replacement-option release-install-confirmation ${confirmed ? "selected" : ""}`}
              >
                <input
                  type="checkbox"
                  checked={confirmed}
                  disabled={!installAvailable}
                  onChange={(event) => setConfirmed(event.target.checked)}
                />
                <span>
                  <strong>
                    {binding ? t("release.candidate.confirmVerify") : installConfirmation}
                  </strong>
                  <small>{t("release.candidate.confirmNote")}</small>
                </span>
              </label>}
              {error ? <InlineError message={error} /> : null}
              <div className="dialog-actions">
                <button
                  className="secondary-button"
                  type="button"
                  onClick={() => void discard()}
                >
                  {t("release.candidate.discard")}
                </button>
                {installable && <button
                  className="primary-button"
                  type="button"
                  disabled={!confirmed || !installAvailable}
                  onClick={() => void install()}
                >
                  <ShieldCheck size={18} /> {binding ? t("release.candidate.verify") : t("release.candidate.install")}
                </button>}
              </div>
              <p className="form-footnote">
                <LockKey size={15} /> {t("release.candidate.footnote")}
              </p>
            </div>
          ) : (
            <form className="release-update-form" onSubmit={check}>
              <div className="segmented-control release-channel-tabs">
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
              <Field
                label={t("release.form.source")}
                hint={t("release.form.sourceHint")}
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
              {error ? <InlineError message={error} /> : null}
              <button
                className="primary-button release-check-button"
                type="submit"
                disabled={!source.trim() || Boolean(busy) || recoveryBusy}
              >
                {busy === "checking" ? (
                  <ArrowClockwise className="spin" size={18} />
                ) : (
                  <ShieldCheck size={18} />
                )}
                {busy === "checking"
                  ? t("release.form.checking")
                  : t("release.form.check")}
              </button>
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
