import { useEffect, useId, useRef, useState } from "react";
import * as Dialog from "@radix-ui/react-dialog";
import { DialogContent } from "../../components/DialogContent";
import { CopyValue } from "../../components/CopyValue";
import { Field, InlineError } from "../../components/ui";
import { api } from "../../api";
import { errorMessage } from "../../lib/errors";
import { useSshLogin } from "../../hooks/useSshLogin";
import { useSshHostTrust, type InspectedSshHost } from "../../hooks/useSshHostTrust";
import { SshLoginFields } from "./SshLoginFields";
import { SshHostVerification } from "./SshHostVerification";
import type { ServerProfile } from "../../types";
import { rememberedReleaseSource, rememberReleaseSource, validReleaseSource, type VpsBaselineCandidate, type VpsReleaseCandidate, type VpsReleaseOperation, type VpsReleaseStatus } from "./vpsRelease";

export function VpsUpdateDialog({ profile, open, onOpenChange, disconnected, onCompleted }: {
  profile: ServerProfile; open: boolean; onOpenChange: (value: boolean) => void;
  disconnected: boolean; onCompleted: () => Promise<void>;
}) {
  const sourceHelpId = useId();
  const loginFormId = useId();
  const login = useSshLogin(profile.endpoint.host, open);
  const trust = useSshHostTrust(profile.endpoint.host, Number(login.port), open);
  const generation = useRef(0);
  const active = useRef(open);
  const isCurrent = (epoch: number) => active.current && generation.current === epoch;
  const [step, setStep] = useState<"login" | "fingerprint" | "release">("login");
  const [fingerprint, setFingerprint] = useState<string | null>(null);
  const [confirmedHost, setConfirmedHost] = useState(false);
  const [status, setStatus] = useState<VpsReleaseStatus | null>(null);
  const [candidate, setCandidate] = useState<VpsReleaseCandidate | null>(null);
  const [baseline, setBaseline] = useState<VpsBaselineCandidate | null>(null);
  const [source, setSource] = useState("");
  const [editingSource, setEditingSource] = useState(false);
  const [channel, setChannel] = useState<"stable" | "preview">("stable");
  const [automatic, setAutomatic] = useState(false);
  const [rollbackConfirmed, setRollbackConfirmed] = useState(false);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [scheduleError, setScheduleError] = useState<string | null>(null);
  const [scheduleMessage, setScheduleMessage] = useState<string | null>(null);
  const configured = Boolean(status?.release.installed);
  const scheduleDirty = Boolean(status && (automatic !== status.security_updates.enabled ||
    (automatic && source !== status.security_updates.source)));

  useEffect(() => {
    generation.current += 1; active.current = open;
    return () => {
      generation.current += 1; active.current = false;
      void api.discardVpsBaseline(profile.id).catch(() => {});
    };
  }, [open, profile.id]);

  useEffect(() => {
      login.clearSecrets(); trust.reset(); setStep("login"); setFingerprint(null);
      setConfirmedHost(false); setStatus(null); setCandidate(null); setBaseline(null); setSource(rememberedReleaseSource(profile.id));
      void api.discardVpsBaseline(profile.id).catch(() => {});
      setChannel("stable"); setAutomatic(false); setRollbackConfirmed(false);
      setBusy(null); setError(null); setMessage(null);
      setEditingSource(false); setScheduleError(null); setScheduleMessage(null);
  }, [open, profile.id]);

  async function request<T>(operation: VpsReleaseOperation, verified = fingerprint): Promise<T> {
    if (!verified) throw new Error("Verify the VPS SSH identity first.");
    const epoch = generation.current;
    if (!isCurrent(epoch)) throw new Error("The VPS operation was cancelled.");
    const credentials = await login.prepare(verified);
    if (!isCurrent(epoch)) throw new Error("The VPS operation was cancelled.");
    const result = await api.manageVpsRelease<T>({ server_id: profile.id,
      ssh: { host: profile.endpoint.host, ...credentials }, operation });
    if (!isCurrent(epoch)) throw new Error("The VPS operation was cancelled.");
    return result;
  }

  async function loadStatus(verified = fingerprint) {
    const current = await request<VpsReleaseStatus>({ action: "status" }, verified);
    setStatus(current);
    return current;
  }

  async function accept(checked: InspectedSshHost | null = trust.inspection) {
    const epoch = generation.current;
    if (!checked || (checked.status !== "trusted" && !confirmedHost)) return;
    setBusy("Reading installed version and update settings…"); setError(null);
    try {
      const verified = await trust.accept(checked, confirmedHost);
      if (!isCurrent(epoch)) return;
      setFingerprint(verified);
      setStep("release");
      const current = await loadStatus(verified);
      setSource(current.security_updates.source ?? rememberedReleaseSource(profile.id)); setAutomatic(current.security_updates.enabled);
      setChannel(current.release.installed?.channel ?? "stable");
      setStep("release");
    } catch (reason) { if (isCurrent(epoch)) setError(errorMessage(reason, "The VPS release state could not be read.")); }
    finally { if (isCurrent(epoch)) setBusy(null); }
  }

  async function inspect() {
    const epoch = generation.current;
    if (!login.valid) return;
    setBusy("Verifying SSH identity…"); setError(null);
    try {
      const checked = await trust.inspect();
      if (!checked || !isCurrent(epoch)) return;
      if (checked.status === "trusted") await accept(checked);
      else { setConfirmedHost(false); setStep("fingerprint"); }
    } catch (reason) { if (isCurrent(epoch)) setError(errorMessage(reason, "The VPS could not be reached.")); }
    finally { if (isCurrent(epoch)) setBusy(null); }
  }

  async function check() {
    const epoch = generation.current;
    if (!validReleaseSource(source)) return;
    setBusy("Downloading and verifying the VPS release…"); setError(null); setMessage(null); setCandidate(null);
    try {
      const checked = await request<VpsReleaseCandidate>({ action: "check", source, channel });
      if (!isCurrent(epoch)) return;
      // An existing matching release can be registered without reinstalling it.
      // A different first release needs the separately reviewed guarded installer.
      if (!configured && !checked.can_install && checked.action !== "already_bound") {
        await prepareBaseline();
      } else { setCandidate(checked); rememberReleaseSource(profile.id, source); }
    }
    catch (reason) { if (isCurrent(epoch)) setError(errorMessage(reason, "The release check failed.")); }
    finally { if (isCurrent(epoch)) setBusy(null); }
  }

  async function perform(operation: VpsReleaseOperation, label: string, completed: string, expectedVersion?: string) {
    const epoch = generation.current;
    setBusy(label); setError(null); setMessage(null);
    try {
      await request(operation);
      setCandidate(null); setRollbackConfirmed(false);
      const next = await loadStatus();
      if (expectedVersion && (next.release.installed?.active_release_version !== expectedVersion || !next.installed_binary_matches))
        throw new Error("The VPS did not confirm the reviewed version after installation. Refresh its state before retrying.");
      await onCompleted();
      if (isCurrent(epoch)) setMessage(completed);
    } catch (reason) {
      // An interrupted transaction may now require recovery. Read it before
      // offering another install, without hiding the original failure.
      if (isCurrent(epoch)) {
        try { await loadStatus(); } catch { /* Keep the last known state and error. */ }
        if (isCurrent(epoch)) setError(errorMessage(reason, "The VPS release operation stopped. Refresh its release state before retrying."));
      }
    }
    finally { if (isCurrent(epoch)) setBusy(null); }
  }

  async function saveSchedule() {
    const epoch = generation.current;
    const requested = automatic;
    const requestedSource = requested ? source : null;
    if (requested && !validReleaseSource(source)) return;
    setBusy("Saving the update schedule…"); setScheduleError(null); setScheduleMessage(null);
    try {
      await request({ action: "configure", enabled: requested, source: requestedSource });
      const saved = await loadStatus();
      if (saved.security_updates.enabled !== requested ||
          (requested && saved.security_updates.source !== requestedSource))
        throw new Error("The VPS did not confirm the requested schedule. Check its saved settings before retrying.");
      if (isCurrent(epoch)) setScheduleMessage(requested ? "Automatic security updates: enabled and saved." : "Automatic security updates: disabled and saved.");
    } catch (reason) { if (isCurrent(epoch)) setScheduleError(errorMessage(reason, "The update schedule could not be saved.")); }
    finally { if (isCurrent(epoch)) setBusy(null); }
  }

  async function baselineAccess() {
    if (!fingerprint) throw new Error("Verify the VPS SSH identity first.");
    const epoch = generation.current;
    const credentials = await login.prepare(fingerprint);
    if (!isCurrent(epoch)) throw new Error("The update review has closed.");
    return { server_id: profile.id, ssh: { host: profile.endpoint.host, ...credentials } };
  }
  async function prepareBaseline() {
    const epoch = generation.current;
    if (!validReleaseSource(source)) return;
    setBusy("Verifying the release and checking this VPS…"); setError(null); setMessage(null); setBaseline(null); setCandidate(null);
    try {
      const prepared = await api.prepareVpsBaseline({ ...await baselineAccess(), source, channel });
      if (isCurrent(epoch)) { setBaseline(prepared); rememberReleaseSource(profile.id, source); }
    }
    catch (reason) { if (isCurrent(epoch)) setError(errorMessage(reason, "The signed baseline could not be prepared.")); }
    finally { if (isCurrent(epoch)) setBusy(null); }
  }
  async function installBaseline() {
    const epoch = generation.current;
    if (!baseline || !disconnected) return;
    setBusy("Installing verified server software and finishing setup…"); setError(null); setMessage(null);
    try {
      await api.installVpsBaseline({ ...await baselineAccess(), manifest_sha256: baseline.manifest_sha256 });
      if (!isCurrent(epoch)) return;
      setBaseline(null); setCandidate(null);
      const next = await loadStatus();
      if (next.release.installed?.active_release_version !== baseline.release_version || !next.installed_binary_matches)
        throw new Error("The VPS did not confirm the reviewed version after installation. Refresh its state before retrying.");
      await onCompleted();
      if (isCurrent(epoch)) setMessage("Update setup is complete. The verified release is installed.");
    } catch (reason) { if (isCurrent(epoch)) setError(errorMessage(reason, "The guarded baseline installation stopped. Refresh the VPS state before retrying.")); }
    finally { if (isCurrent(epoch)) setBusy(null); }
  }

  const verifiedVersion = baseline?.release_version ?? candidate?.release_version;
  const canFinish = Boolean(baseline || (candidate?.can_install && candidate.action !== "already_bound"));
  const clearReview = () => { setCandidate(null); setBaseline(null); setMessage(null); setScheduleMessage(null); };
  const finish = () => baseline ? installBaseline() : candidate ? perform(
    { action: "install", manifest_sha256: candidate.manifest_sha256 }, "Installing the verified VPS release…",
    candidate.baseline_required ? "Update setup is complete. The installed release has been verified." : `Version ${candidate.release_version} is installed.`,
    candidate.release_version,
  ) : Promise.resolve();
  const primaryLabel = configured ? `Install update ${verifiedVersion}` : baseline ? `Install ${verifiedVersion} & finish setup` : "Finish setup";

  return <Dialog.Root open={open} onOpenChange={(next) => { if (!busy) onOpenChange(next); }}>
    <Dialog.Portal><Dialog.Overlay className="dialog-overlay" />
      <DialogContent className="dialog-content repair-server-dialog"
        heading={step === "release" && !configured ? `Set up updates for ${profile.name}` : `Update ${profile.name}`}
        description={step === "release" ? configured ? "Check for a verified release and review it before installation." : "Choose a release source, verify this VPS, then finish setup." : "Use SSH to read the installed version and update settings on your VPS."}
        closeDisabled={Boolean(busy)}
        footer={<>
          {busy ? <div className="workflow-progress" role="status"><strong>{busy}</strong><p>Wait for this operation to finish before closing. Server maintenance cannot be interrupted here.</p></div> : <>
            <Dialog.Close asChild><button type="button" className="secondary-button">{step === "release" ? "Close" : "Cancel"}</button></Dialog.Close>
            {step === "login" && <button type="submit" form={loginFormId} className="primary-button" disabled={!login.valid}>Continue</button>}
            {step === "fingerprint" && <button className="primary-button" disabled={!confirmedHost} onClick={() => void accept()}>Fingerprint matches — continue</button>}
            {step === "release" && (canFinish
              ? <button className="primary-button" disabled={!disconnected || Boolean(status?.release.recovery_pending)} onClick={() => void finish()}>{primaryLabel}</button>
              : <button className="primary-button" disabled={!validReleaseSource(source) || Boolean(status?.release.recovery_pending)} onClick={() => void (status ? check() : prepareBaseline())}>{configured ? "Check for updates" : "Verify release"}</button>)}
          </>}
        </>}>
        {step === "login" && <form id={loginFormId} className="uninstall-form" onSubmit={(event) => { event.preventDefault(); void inspect(); }}>
          <fieldset disabled={Boolean(busy)} className="ssh-operation-fields"><SshLoginFields login={login} /></fieldset>
        </form>}
        {step === "fingerprint" && trust.inspection && <fieldset disabled={Boolean(busy)} className="ssh-operation-fields">
          <SshHostVerification inspection={trust.inspection} confirmed={confirmedHost} onConfirmed={setConfirmedHost} />
        </fieldset>}
        {step === "release" && <div className="update-workflow">
          {!configured && <>
            <ol className="setup-progress" aria-label="Update setup progress">
              <li aria-current={!validReleaseSource(source) ? "step" : undefined} data-complete={validReleaseSource(source)}>Choose source</li>
              <li aria-current={validReleaseSource(source) && !canFinish ? "step" : undefined} data-complete={canFinish}>Verify release</li>
              <li aria-current={canFinish ? "step" : undefined}>Finish setup</li>
            </ol>
            <div><h3>Updates are not configured for this installation</h3>
              <p>Use the release source supplied by your SirinVPN distributor or the person who installed this VPS. Verification checks the release signature and compatibility before you can finish.</p>
              {!status && <p className="settings-note">The installed version could not be established. Setup can verify and install server software over SSH.</p>}
            </div>
          </>}
          {configured && <dl className="update-versions">
            <div><dt>Installed version</dt><dd>{status!.release.installed!.active_release_version}</dd></div>
            <div><dt>Available version</dt><dd>{verifiedVersion ?? "Not checked yet"}</dd></div>
          </dl>}
          {status?.release.installed && !status.installed_binary_matches && <InlineError message="The installed software differs from its verified receipt. Repair with the matching signed build before updating." />}
          {status?.automatic_outcome === "failed" && <InlineError message="The latest automatic security update failed. Check the source and current release state before retrying." />}
          {status?.release.recovery_pending && <div className="maintenance-prerequisite"><p>An interrupted update needs recovery before another release can be checked.</p>
            <button className="secondary-button" disabled={Boolean(busy) || !disconnected} onClick={() => void perform({ action: "recover" }, "Recovering the VPS update…", "The interrupted update has been recovered.")}>Recover interrupted update</button>
          </div>}
          <fieldset className="ssh-operation-fields update-source" disabled={Boolean(busy)}>
            {!configured || editingSource || !source ? <>
              <Field label="Release source"><input type="url" aria-describedby={sourceHelpId} value={source} placeholder="HTTPS release directory" onChange={(event) => { setSource(event.target.value); clearReview(); }} /></Field>
              <p id={sourceHelpId} className="field-help">Use an HTTPS directory ending in /. The address chooses where to download; it cannot add or change trusted signing keys.</p>
            </> : <div className="update-source-saved"><span>Release source</span><p>{source}</p><button className="text-button" onClick={() => setEditingSource(true)}>Change source</button></div>}
            <Field label="Release channel"><select value={channel} onChange={(event) => { setChannel(event.target.value as typeof channel); clearReview(); }}><option value="stable">Stable</option><option value="preview">Preview</option></select></Field>
          </fieldset>
          {(candidate || baseline) && <section className="update-review" aria-label="Verified release">
            <h3>{candidate?.action === "already_bound" ? "You have this release" : `Verified release ${verifiedVersion}`}</h3>
            <p>{candidate?.action === "already_bound" ? "This signed release is already installed." : baseline ? "Finishing setup installs this verified release and preserves your VPS identity and access state. VPS services will restart briefly." : candidate?.baseline_required ? "Your installed software matches the verified release. Finish setup to register it for future updates." : "Installation briefly restarts VPS services. If the health check fails, the previous signed release is restored."}</p>
            {candidate && !candidate.can_install && candidate.action !== "already_bound" && <p>This release cannot be installed on the current VPS state.</p>}
              <dl className="result-facts"><div><dt>Verification</dt><dd>Signature and software hash verified</dd></div>
              <div><dt>Compatibility</dt><dd>{baseline || candidate?.can_install || candidate?.action === "already_bound" ? "Compatible with this VPS" : "Installation not available for the current VPS state"}</dd></div>
              <div><dt>Release type</dt><dd>{(baseline?.security_update ?? candidate?.security_update) ? "Security update" : "Standard release"}</dd></div></dl>
            <details className="result-disclosure"><summary>Verified software details</summary>
              <p>{baseline?.artifact.target ?? candidate?.artifact_target} · {((baseline?.artifact.size_bytes ?? candidate?.artifact_size_bytes ?? 0) / 1024 / 1024).toFixed(1)} MB</p>
              <div className="result-identity"><span>Software SHA-256</span><CopyValue label="Software SHA-256" value={baseline?.artifact.sha256 ?? candidate?.artifact_sha256 ?? ""} showCopyLabel /></div>
            </details>
          </section>}
          {(configured || status?.security_updates.enabled) && <section className="update-schedule">
            <h3>Automatic security updates</h3>
            <p className="schedule-state" role="status">{status?.security_updates.enabled ? "Enabled on the VPS" : "Disabled on the VPS"}{scheduleDirty ? " · Changes not yet saved" : " · Saved"}</p>
            <fieldset className="ssh-operation-fields" disabled={Boolean(busy)}>
              <label className="replacement-option"><input type="checkbox" checked={automatic} onChange={(event) => { setAutomatic(event.target.checked); setScheduleError(null); setScheduleMessage(null); }} /><span><strong>Automatic security updates</strong></span></label>
              <p className="field-help">Once daily, the VPS checks this source for newer stable security releases. Signature, compatibility, and rollback checks still apply.</p>
              <button className="secondary-button" disabled={!scheduleDirty || (automatic && (!configured || !validReleaseSource(source)))} onClick={() => void saveSchedule()}>Save schedule</button>
            </fieldset>
            {scheduleError && <><p className="field-help">Could not save the schedule.</p><InlineError message={scheduleError} /></>}
            {scheduleMessage && <p role="status">{scheduleMessage}</p>}
          </section>}
          {status?.release.rollback_version && <details className="result-disclosure"><summary>Restore previous version {status.release.rollback_version}</summary>
            <fieldset className="ssh-operation-fields" disabled={Boolean(busy)}><label className="replacement-option"><input type="checkbox" checked={rollbackConfirmed} onChange={(event) => setRollbackConfirmed(event.target.checked)} /><span><strong>Restore version {status.release.rollback_version}</strong></span></label>
              <p className="field-help">The retained release must still be trusted and compatible with current server state.</p>
              <button className="secondary-button" disabled={!rollbackConfirmed || !disconnected} onClick={() => void perform({ action: "rollback", confirmed: true }, "Restoring the previous signed release…", "The previous signed VPS release is restored.")}>Roll back VPS release</button>
            </fieldset>
          </details>}
          <details className="result-disclosure"><summary>Download privacy and verification</summary><p>Routine checks download to the VPS. First-time installation downloads to this computer, then transfers the verified software over SSH. Requests contain no device, server, user, or installation identifiers.</p><p>The last verified source is saved on this computer for this VPS. Signing authority comes from the trusted keys included with SirinVPN. A custom source must provide a release signed by an already trusted key.</p></details>
          {!disconnected && <p className="field-help">Disconnect this computer before installing, recovering, or rolling back VPS software.</p>}
          <button className="text-button" disabled={Boolean(busy)} onClick={() => setStep("login")}>Change SSH login</button>
        </div>}
        {message && <p className="workflow-message" role="status">{message}</p>}
        {error && <InlineError message={error} />}
      </DialogContent>
    </Dialog.Portal>
  </Dialog.Root>;
}
