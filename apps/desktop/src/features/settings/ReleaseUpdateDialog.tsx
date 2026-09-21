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
  const packageLabel = android ? "Android APK" : windows ? "Windows package" : appimage ? "AppImage" : "Debian package";

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
    catch (reason) { setError(errorMessage(reason, "The temporary download could not be discarded. Retry.")); }
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
      setError(
        errorMessage(
          reason,
          "The source did not provide a root-authenticated release for this build.",
        ),
      );
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
          windows
            ? "The Windows update did not complete. Retry the same authenticated package; its recovery state and any accepted trust-policy update are retained."
            : appimage ? "The AppImage replacement could not be confirmed. Reopen app updates to reconcile the installed file. The signed recovery packages are retained."
            : "The package update did not complete. The coordinator attempted rollback and retained recovery state if it could not prove completion; a root-authenticated trust-policy update may remain active.",
        ),
      );
    } finally {
      setBusy(null);
    }
  };

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
          heading={<>{installed ? candidate?.baseline_bound ? "Signed baseline verified" : android ? "Android installer requested" : windows ? "Windows installer opened" : "Update installed" : "Check for app updates"}</>}
          description={<>Contact only a release directory you choose. SirinVPN attaches no
            device, account, installation, or VPS identifier.</>}
          closeDisabled={Boolean(busy) || recoveryBusy} closeLabel="Close app updates">

          {installed && candidate ? (
            <div className="backup-success release-update-success">
              <span>
                <Check size={26} weight="bold" />
              </span>
              <h3>{candidate.baseline_bound ? `SirinVPN ${candidate.release_version} is verified` : windows ? `Install SirinVPN ${candidate.release_version}` : `SirinVPN ${candidate.release_version} is installed`}</h3>
              <p>
                {candidate.baseline_bound ? "This installed package now has a signed baseline. You can check a newer release source to update it."
                  : android ? "Complete Android’s installation approval. Installation can interrupt the VPN. Android controls app downgrade availability." : windows ? "Complete the Windows installer, then reopen SirinVPN."
                  : appimage ? "Close and reopen the same AppImage to run the new version. The previous signed version remains available for rollback."
                  : "The authenticated Debian transaction completed. Close and reopen SirinVPN to run the new application version."}
              </p>
              <button
                className="primary-button"
                type="button"
                onClick={() => changeOpen(false)}
              >
                {android || windows || candidate.baseline_bound ? "Close" : "Close SirinVPN later"}
              </button>
            </div>
          ) : busy === "installing" ? (
            <div className="uninstall-progress release-update-progress">
              <ArrowClockwise className="spin" size={27} />
              <strong>{binding ? "Verifying the installed package" : "Installing the authenticated package"}</strong>
              <p>
                {binding ? "The signed release must match the exact installed bytes."
                  : android ? "Review Android’s installation prompt. The APK signature and signed release are checked before installation. Android controls downgrade availability." : appimage ? "The complete verified AppImage replaces the current file atomically. A signed copy of the previous version is kept for recovery."
                  : windows ? "Approve the Windows update prompt. SirinVPN will close once the verified installer is ready. Your selected protection policy is retained while the VPN service restarts." : "Keep SirinVPN open. Package health is verified before the installed-release receipt advances; failure attempts authenticated restoration and retains recovery state if completion cannot be proven."}
              </p>
            </div>
          ) : candidate ? (
            <div className="release-candidate">
              <div className="release-candidate-heading">
                <span className="release-authenticated">
                  <ShieldCheck size={16} weight="fill" /> Root-authenticated
                </span>
                {candidate.security_update ? (
                  <span className="release-security-label">
                    Security update
                  </span>
                ) : null}
                <h3>SirinVPN {candidate.release_version}</h3>
                <p>
                  Sequence {candidate.release_sequence} · {candidate.channel}{" "}
                  channel · running {candidate.current_version}
                </p>
              </div>
              <p>Verified version {candidate.release_version} for this device · {formatBytes(candidate.artifact_size_bytes)}</p>
              <p className="settings-note">Release source: {source}</p>
              <details className="release-verification-details"><summary>Signature and package details</summary>
              <div className="release-detail-grid">
                <div>
                  <span>Package</span>
                  <strong>{candidate.artifact_file_name}</strong>
                </div>
                <div>
                  <span>Download</span>
                  <strong>{formatBytes(candidate.artifact_size_bytes)}</strong>
                </div>
                <div>
                  <span>Target</span>
                  <strong>{candidate.artifact_target}</strong>
                </div>
                <div>
                  <span>Trust policy</span>
                  <strong>Sequence {candidate.trust_policy_sequence}</strong>
                </div>
                <div>
                  <span>Trust root</span>
                  <code title={candidate.root_key_id_sha256}>
                    {candidate.root_key_id_sha256}
                  </code>
                </div>
                <div>
                  <span>Release signer</span>
                  <code title={candidate.release_key_id_sha256}>
                    {candidate.release_key_id_sha256}
                  </code>
                </div>
              </div>
              <div className="release-digest">
                <span>Verified package SHA-256</span>
                <code>{candidate.artifact_sha256}</code>
              </div>

              </details>

              {binding ? <p className="settings-note">Verify the signed copy of this installed version once to enable future updates.</p> : !candidate.newer_than_running ? (
                <div className="warning-note replacement-warning">
                  <Warning size={18} weight="fill" />
                  <span>
                    This authenticated candidate is not newer than the running
                    build. This screen never performs rollback.
                  </span>
                </div>
              ) : !nativeAvailable ? (
                <div className="warning-note replacement-warning">
                  <Warning size={18} weight="fill" />
                  <span>
                    {windows ? "The download is verified. Install the packaged Windows application before using in-app updates." : "The download is verified. In-app installation requires the installed Debian application or a supported, user-owned AppImage."}
                  </span>
                </div>
              ) : !ready ? (
                <div className="warning-note replacement-warning">
                  <Warning size={18} weight="fill" />
                  <span>
                    Disconnect SirinVPN and disable persistent protection before installing. The verified candidate is retained during this app session while you review connection settings.
                  </span>
                </div>
              ) : null}

              {!ready && <button className="secondary-button" onClick={() => { changeOpen(false); onReviewPrerequisites?.(); }}>Review connection prerequisites</button>}
              <label
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
                    {binding ? "I confirm verification of this installed package" : `I confirm installation of this exact authenticated ${packageLabel}`}
                  </strong>
                  <small>
                    The root-signed key policy is applied first and may remain
                    active if package installation later fails. Retrying this
                    exact candidate is safe.
                  </small>
                </span>
              </label>
              {error ? <InlineError message={error} /> : null}
              <div className="dialog-actions">
                <button
                  className="secondary-button"
                  type="button"
                  onClick={() => void discard()}
                >
                  Discard
                </button>
                <button
                  className="primary-button"
                  type="button"
                  disabled={!confirmed || !installAvailable}
                  onClick={() => void install()}
                >
                  <ShieldCheck size={18} /> {binding ? "Verify installed release" : "Install authenticated update"}
                </button>
              </div>
              <p className="form-footnote">
                <LockKey size={15} /> The source URL and check result are not
                saved across app restarts. Discard removes the temporary download; signed packages
                needed for installation or rollback remain in private storage.
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
                  Stable
                </button>
                <button
                  type="button"
                  aria-pressed={channel === "preview"}
                  disabled={Boolean(busy)}
                  onClick={() => setChannel("preview")}
                >
                  Preview
                </button>
              </div>
              <Field
                label="Release source"
                hint="Explicit HTTPS base directory ending in /. This value is used for this check only."
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
                  <strong>A check downloads one complete package.</strong>
                  <span>
                    Four bounded metadata files are authenticated first, then
                    only this platform's signed package is downloaded.
                  </span>
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
                  ? "Authenticating and downloading"
                  : "Check and verify release"}
              </button>
              <p className="form-footnote">
                <GlobeHemisphereWest size={15} /> The chosen host and network
                can observe your IP, request timing, channel path, and platform
                package name.
              </p>
              <ReleaseRecovery busy={Boolean(busy) || recoveryBusy} setBusy={setRecoveryBusy} />
            </form>
          )}
        </DialogContent>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
