import { useEffect, useId, useRef, useState } from "react";
import * as Dialog from "@radix-ui/react-dialog";
import { Check, Warning, Wrench } from "@phosphor-icons/react";
import { DialogBack, DialogContent } from "../../components/DialogContent";
import { HashValue } from "../../components/CopyValue";
import { Busy, OperationResult } from "../../components/OperationResult";
import { Field, InlineError } from "../../components/ui";
import { api } from "../../api";
import { errorMessage } from "../../lib/errors";
import { confirmAction } from "../../lib/confirmAction";
import { t } from "../../i18n";
import { formatBytes, formatTarget } from "../../format";
import { useSshOperation } from "../../hooks/useSshOperation";
import type { InspectedSshHost } from "../../hooks/useSshHostTrust";
import { SshLoginFields } from "./SshLoginFields";
import { SshHostVerification } from "./SshHostVerification";
import type { ServerProfile, SshCredentials } from "../../types";
import { completeReleaseSource, rememberAppReleaseSource, rememberedReleaseSource, rememberReleaseSource, validReleaseSource, type VpsBaselineCandidate, type VpsReleaseCandidate, type VpsReleaseOperation, type VpsReleaseStatus } from "./vpsRelease";
import { SettingsDisclosure } from "./SettingsParts";

/** What the VPS reported about its release; unknown until read, or when a legacy VPS can't say. */
type ReleaseStatus = { kind: "unknown" } | { kind: "loaded"; status: VpsReleaseStatus };
/** The verified release waiting for the install action. */
type Review = { kind: "none" } | { kind: "candidate"; candidate: VpsReleaseCandidate } | { kind: "baseline"; baseline: VpsBaselineCandidate };
/** The last action's outcome: a success and an error are never shown together. */
type Outcome = { kind: "none" } | { kind: "done"; message: string } | { kind: "failed"; message: string; retry?: () => void };
type ScheduleOutcome = { kind: "none" } | { kind: "done"; message: string } | { kind: "failed"; message: string; requested: boolean };
/** The status read that opens the release step; a legacy VPS without the release tool reports an error. */
type SignIn = { status: VpsReleaseStatus } | { status: null; error: unknown };

export function VpsUpdateDialog({ profile, open, onOpenChange, disconnected, onCompleted, onRepair }: {
  profile: ServerProfile; open: boolean; onOpenChange: (value: boolean) => void;
  disconnected: boolean; onCompleted: () => Promise<void>;
  /** Opens repair for this VPS; offered when the installed software doesn't match its signed record. */
  onRepair?: () => void;
}) {
  const loginFormId = useId();
  const op = useSshOperation<SignIn>(profile.endpoint.host, open);
  const { login, trust, view } = op;
  const generation = useRef(0);
  const active = useRef(open);
  const isCurrent = (epoch: number) => active.current && generation.current === epoch;
  const [releaseStatus, setReleaseStatus] = useState<ReleaseStatus>({ kind: "unknown" });
  const [review, setReview] = useState<Review>({ kind: "none" });
  const [sourceText, setSource] = useState("");
  // Only an address typed here may become the app's own source; one the VPS reported may not.
  const typedSource = useRef(false);
  // A folder address typed without its trailing "/" still counts; the field shows it once left.
  const source = completeReleaseSource(sourceText);
  const [editingSource, setEditingSource] = useState(false);
  const [channel, setChannel] = useState<"stable" | "preview">("stable");
  const [automatic, setAutomatic] = useState(false);
  const [busy, setBusy] = useState<string | null>(null);
  const [verifying, setVerifying] = useState(false);
  const [outcome, setOutcome] = useState<Outcome>({ kind: "none" });
  const [scheduleOutcome, setScheduleOutcome] = useState<ScheduleOutcome>({ kind: "none" });
  const status = releaseStatus.kind === "loaded" ? releaseStatus.status : null;
  const candidate = review.kind === "candidate" ? review.candidate : null;
  const baseline = review.kind === "baseline" ? review.baseline : null;
  // The key the release step signed in with; requests there reuse it.
  const fingerprint = view === "succeeded" ? trust.inspection?.fingerprint ?? null : null;
  const configured = Boolean(status?.release.installed);
  const mismatch = Boolean(status?.release.installed && !status.installed_binary_matches);
  const recoveryPending = Boolean(status?.release.recovery_pending);
  const savedSchedule = status?.security_updates;
  const working = op.busy || busy !== null;
  const busyLabel = op.state.kind === "verifyingHost" ? t("vps.update.busy.verifyingKey")
    : op.state.kind === "running" ? t("vps.update.busy.reading") : busy;

  useEffect(() => {
    generation.current += 1; active.current = open;
    return () => {
      generation.current += 1; active.current = false;
      void api.discardVpsBaseline(profile.id).catch(() => {});
    };
  }, [open, profile.id]);

  const { reset: resetOperation } = op;
  useEffect(() => {
    resetOperation();
    setReleaseStatus({ kind: "unknown" }); setReview({ kind: "none" }); setSource(rememberedReleaseSource(profile.id)); typedSource.current = false;
    void api.discardVpsBaseline(profile.id).catch(() => {});
    setChannel("stable"); setAutomatic(false); setVerifying(false);
    setBusy(null); setOutcome({ kind: "none" });
    setEditingSource(false); setScheduleOutcome({ kind: "none" });
  }, [open, profile.id, resetOperation]);

  const fail = (epoch: number, reason: unknown, fallback: string, retry?: () => void) => {
    if (isCurrent(epoch)) setOutcome({ kind: "failed", message: errorMessage(reason, fallback), retry });
  };

  /** Prepares the login for one request; its save runs once that request worked. */
  function access(epoch: number) {
    if (!fingerprint) throw new Error(t("vps.update.error.notVerified"));
    if (!isCurrent(epoch)) throw new Error(t("vps.update.error.cancelled"));
    return login.prepare(fingerprint);
  }

  async function request<T>(operation: VpsReleaseOperation): Promise<T> {
    const epoch = generation.current;
    const { credentials, save } = access(epoch);
    const result = await api.manageVpsRelease<T>({ server_id: profile.id,
      ssh: { host: profile.endpoint.host, ...credentials }, operation });
    if (!isCurrent(epoch)) throw new Error(t("vps.update.error.cancelled"));
    await save();
    return result;
  }

  function showStatus(current: VpsReleaseStatus) {
    setReleaseStatus({ kind: "loaded", status: current });
    setAutomatic(current.security_updates.enabled);
  }

  async function loadStatus() {
    const current = await request<VpsReleaseStatus>({ action: "status" });
    showStatus(current);
    return current;
  }

  async function retryStatus() {
    const epoch = generation.current;
    setBusy(t("vps.update.busy.reading")); setOutcome({ kind: "none" });
    try { await loadStatus(); }
    catch (reason) { fail(epoch, reason, t("vps.update.error.status"), () => void retryStatus()); }
    finally { if (isCurrent(epoch)) setBusy(null); }
  }

  /** Signs in with the pinned key and reads the release status, which opens the release step. */
  async function accept(checked: InspectedSshHost | null = trust.inspection) {
    const epoch = generation.current;
    if (!checked || (checked.status !== "trusted" && !trust.confirmed)) return;
    setOutcome({ kind: "none" });
    const signedIn = await op.run(async credentials => {
      try {
        return { status: await api.manageVpsRelease<VpsReleaseStatus>({ server_id: profile.id,
          ssh: { host: profile.endpoint.host, ...credentials }, operation: { action: "status" } }) };
      } catch (error) { return { status: null, error }; }
    }, t("vps.update.error.status"), { inspection: checked, loginWorked: result => result.status !== null, keepSecrets: true });
    if (!signedIn || !isCurrent(epoch)) return;
    if (signedIn.status) {
      showStatus(signedIn.status);
      setSource(signedIn.status.security_updates.source ?? rememberedReleaseSource(profile.id));
      setChannel(signedIn.status.release.installed?.channel ?? "stable");
    } else {
      setReleaseStatus({ kind: "unknown" });
      fail(epoch, signedIn.error, t("vps.update.error.status"), () => void retryStatus());
    }
  }

  async function inspect() {
    if (!login.valid) return;
    setOutcome({ kind: "none" });
    await op.verify(t("vps.common.error.unreachable"), accept);
  }

  async function check() {
    const epoch = generation.current;
    if (!validReleaseSource(source)) return;
    setBusy(t("vps.update.busy.verifying")); setVerifying(true); setOutcome({ kind: "none" }); setReview({ kind: "none" });
    try {
      const checked = await request<VpsReleaseCandidate>({ action: "check", source, channel });
      if (!isCurrent(epoch)) return;
      // An existing matching release can be registered without reinstalling it.
      // A different first release needs the separately reviewed guarded installer.
      if (!configured && !checked.can_install && checked.action !== "already_bound") {
        await prepareBaseline();
      } else { setReview({ kind: "candidate", candidate: checked }); rememberVerifiedSource(); }
    }
    catch (reason) { fail(epoch, reason, t("vps.update.error.check"), () => void check()); }
    finally { if (isCurrent(epoch)) { setBusy(null); setVerifying(false); } }
  }

  async function perform(operation: VpsReleaseOperation, label: string, completed: string, expectedVersion?: string) {
    const epoch = generation.current;
    setBusy(label); setOutcome({ kind: "none" });
    try {
      await request(operation);
      setReview({ kind: "none" });
      const next = await loadStatus();
      if (expectedVersion && (next.release.installed?.active_release_version !== expectedVersion || !next.installed_binary_matches))
        throw new Error(t("vps.update.error.notConfirmed"));
      await onCompleted();
      if (isCurrent(epoch)) setOutcome({ kind: "done", message: completed });
    } catch (reason) {
      // An interrupted transaction may now require recovery. Read it before
      // offering another install, without hiding the original failure.
      if (isCurrent(epoch)) {
        try { await loadStatus(); } catch { /* Keep the last known state and error. */ }
        fail(epoch, reason, t("vps.update.error.stopped"));
      }
    }
    finally { if (isCurrent(epoch)) setBusy(null); }
  }

  /** Automatic updates save as soon as the switch changes; a failure puts the switch back. */
  async function saveSchedule(requested: boolean) {
    const epoch = generation.current;
    const requestedSource = requested ? source : null;
    if (requested && !validReleaseSource(source)) return;
    const previous = automatic;
    let read = false;
    setAutomatic(requested);
    setBusy(t("vps.update.busy.saving")); setScheduleOutcome({ kind: "none" });
    try {
      await request({ action: "configure", enabled: requested, source: requestedSource });
      const saved = await loadStatus();
      read = true;
      if (saved.security_updates.enabled !== requested ||
          (requested && saved.security_updates.source !== requestedSource))
        throw new Error(t("vps.update.error.scheduleNotConfirmed"));
      if (isCurrent(epoch)) setScheduleOutcome({ kind: "done", message: requested ? t("vps.update.schedule.enabled") : t("vps.update.schedule.disabled") });
    } catch (reason) {
      // After a status read the switch already shows what the VPS saved.
      if (isCurrent(epoch)) {
        if (!read) setAutomatic(previous);
        setScheduleOutcome({ kind: "failed", message: errorMessage(reason, t("vps.update.error.schedule")), requested });
      }
    }
    finally { if (isCurrent(epoch)) setBusy(null); }
  }

  async function rollback(version: string) {
    if (!await confirmAction({
      title: t("vps.update.rollback.confirmTitle", { version }),
      message: t("vps.update.rollback.confirmMessage"),
      confirm: t("vps.update.rollback.confirm"),
    })) return;
    await perform({ action: "rollback", confirmed: true }, t("vps.update.busy.rollingBack"), t("vps.update.done.rolledBack", { version }));
  }

  const baselineAccess = (credentials: SshCredentials) => ({ server_id: profile.id, ssh: { host: profile.endpoint.host, ...credentials } });
  async function prepareBaseline() {
    const epoch = generation.current;
    if (!validReleaseSource(source)) return;
    setBusy(t("vps.update.busy.verifying")); setVerifying(true); setOutcome({ kind: "none" }); setReview({ kind: "none" });
    try {
      const { credentials, save } = access(epoch);
      const prepared = await api.prepareVpsBaseline({ ...baselineAccess(credentials), source, channel });
      if (!isCurrent(epoch)) return;
      await save();
      setReview({ kind: "baseline", baseline: prepared }); rememberVerifiedSource();
    }
    catch (reason) { fail(epoch, reason, t("vps.update.error.check"), () => void prepareBaseline()); }
    finally { if (isCurrent(epoch)) { setBusy(null); setVerifying(false); } }
  }
  async function installBaseline() {
    const epoch = generation.current;
    if (!baseline || !disconnected) return;
    setBusy(t("vps.update.busy.installingSetup")); setOutcome({ kind: "none" });
    try {
      const { credentials, save } = access(epoch);
      await api.installVpsBaseline({ ...baselineAccess(credentials), manifest_sha256: baseline.manifest_sha256 });
      if (!isCurrent(epoch)) return;
      await save();
      setReview({ kind: "none" });
      const next = await loadStatus();
      if (next.release.installed?.active_release_version !== baseline.release_version || !next.installed_binary_matches)
        throw new Error(t("vps.update.error.notConfirmed"));
      await onCompleted();
      if (isCurrent(epoch)) setOutcome({ kind: "done", message: t("vps.update.done.setUp", { version: baseline.release_version }) });
    } catch (reason) { fail(epoch, reason, t("vps.update.error.stopped")); }
    finally { if (isCurrent(epoch)) setBusy(null); }
  }

  const verifiedVersion = baseline?.release_version ?? candidate?.release_version;
  const releaseNotes = baseline?.release_notes ?? candidate?.release_notes;
  const canFinish = Boolean(baseline || (candidate?.can_install && candidate.action !== "already_bound"));
  const sourceValid = validReleaseSource(source);
  const sourceError = source && !sourceValid ? t("vps.update.source.invalid") : undefined;
  const clearReview = () => {
    setReview({ kind: "none" });
    if (outcome.kind === "done") setOutcome({ kind: "none" });
    if (scheduleOutcome.kind === "done") setScheduleOutcome({ kind: "none" });
  };
  const rememberVerifiedSource = () => {
    rememberReleaseSource(profile.id, source);
    if (typedSource.current) rememberAppReleaseSource(source);
  };
  const finish = () => baseline ? installBaseline() : candidate ? perform(
    // Finishing setup on the release already installed is not an update install.
    { action: "install", manifest_sha256: candidate.manifest_sha256 },
    t(configured ? "vps.update.busy.installing" : candidate.baseline_required ? "vps.update.busy.finishing" : "vps.update.busy.installingSetup"),
    candidate.baseline_required ? t("vps.update.done.setUp", { version: candidate.release_version }) : t("vps.update.done.installed", { version: candidate.release_version }),
    candidate.release_version,
  ) : Promise.resolve();
  const primaryLabel = configured ? t("vps.update.action.install", { version: verifiedVersion ?? "" }) : baseline ? t("vps.update.action.installAndFinish") : t("vps.update.action.finishSetup");
  // One reason beside the disabled primary action, most important first.
  const blocker = view === "form" ? login.missing
    : view === "confirmHost" ? (trust.confirmed ? null : t("ssh.verify.confirmFirst"))
    : view === "running" ? null
    : mismatch ? t("vps.update.blocked.mismatch")
    : recoveryPending ? t("vps.update.blocked.recovery")
    : canFinish ? (disconnected ? null : t("vps.update.disconnectFirst"))
    : sourceValid ? null : t("vps.update.blocked.source");
  const steps = [t("vps.update.steps.source"), t("vps.update.steps.verify"), t("vps.update.steps.finish")];
  const currentStep = canFinish ? 2 : verifying ? 1 : 0;
  const sourceDiffers = Boolean(savedSchedule?.enabled && savedSchedule.source && sourceValid && source !== savedSchedule.source);

  return <Dialog.Root open={open} onOpenChange={(next) => { if (!working) onOpenChange(next); }}>
    <Dialog.Portal><Dialog.Overlay className="dialog-overlay" />
      <DialogContent className="dialog-content repair-server-dialog vps-update-dialog"
        data-operation="update" data-flow-state={op.state.kind}
        heading={t("vps.update.title", { name: profile.name })}
        description={view === "succeeded" ? configured ? t("vps.update.description.configured") : t("vps.update.description.setup") : t("vps.update.description.login")}
        closeDisabled={working}
        footerNote={working ? t("vps.common.keepOpen") : blocker}
        footer={<>
          {view === "confirmHost" && <DialogBack disabled={working} onClick={op.back} />}
          <Dialog.Close asChild><button type="button" className="secondary-button" disabled={working}>{view === "succeeded" ? t("common.action.close") : t("common.action.cancel")}</button></Dialog.Close>
          {busyLabel ? <button type="button" className="primary-button" disabled><Busy label={busyLabel} /></button> : <>
            {view === "form" && <button type="submit" form={loginFormId} className="primary-button" disabled={!login.valid}>{t("common.action.continue")}</button>}
            {view === "confirmHost" && <button type="button" className="primary-button" disabled={!trust.confirmed} onClick={() => void accept()}>{t("common.action.continue")}</button>}
            {view === "succeeded" && (canFinish
              ? <button type="button" className="primary-button" disabled={!disconnected || recoveryPending || mismatch} onClick={() => void finish()}>{primaryLabel}</button>
              : <button type="button" className="primary-button" disabled={!sourceValid || recoveryPending || mismatch} onClick={() => void (status ? check() : prepareBaseline())}>{configured ? t("vps.update.action.check") : t("vps.update.action.verify")}</button>)}
          </>}
        </>}>
        {view === "form" && op.error && <InlineError message={op.error} onRetry={() => void inspect()} retryDisabled={working || !login.valid} />}
        {view === "succeeded" && outcome.kind === "failed" && <InlineError message={outcome.message} onRetry={outcome.retry} retryDisabled={working} />}
        {/* The login stays in view while it signs in. */}
        {(view === "form" || view === "running") && <form id={loginFormId} className="uninstall-form" onSubmit={(event) => { event.preventDefault(); void inspect(); }}>
          <fieldset disabled={working} className="ssh-operation-fields"><SshLoginFields login={login} /></fieldset>
        </form>}
        {view === "confirmHost" && trust.inspection && <fieldset disabled={working} className="ssh-operation-fields">
          <SshHostVerification inspection={trust.inspection} confirmed={trust.confirmed} onConfirmed={trust.setConfirmed} />
        </fieldset>}
        {view === "succeeded" && <div className="update-workflow">
          {outcome.kind === "done" && <OperationResult title={outcome.message} />}
          {mismatch && <div className="update-blocker danger" role="alert">
            <Warning size={20} weight="fill" />
            <div><p>{t("vps.update.warning.mismatch")}</p>
              {onRepair && <button type="button" className="secondary-button" disabled={working} onClick={onRepair}><Wrench size={17} />{t("vps.update.action.repair")}</button>}</div>
          </div>}
          {status?.automatic_outcome === "failed" && <div className="update-blocker"><Warning size={20} weight="fill" /><div><p>{t("vps.update.warning.automaticFailed")}</p></div></div>}
          {recoveryPending && <div className="update-blocker">
            <Warning size={20} weight="fill" />
            <div><p>{t("vps.update.recovery.needed")}</p>
              <button type="button" className="secondary-button" disabled={working || !disconnected} onClick={() => void perform({ action: "recover" }, t("vps.update.busy.recovering"), t("vps.update.done.recovered"))}>{t("vps.update.recovery.action")}</button></div>
          </div>}
          {!configured && <>
            <ol className="update-steps" aria-label={t("vps.update.steps.label")}>
              {steps.map((label, index) => <li key={label} data-state={index < currentStep ? "done" : index === currentStep ? "current" : "todo"} aria-current={index === currentStep ? "step" : undefined}>
                <span>{index < currentStep ? <Check size={14} weight="bold" /> : index + 1}</span>{label}
              </li>)}
            </ol>
            {!status && <p className="settings-note">{t("vps.update.statusUnknown")}</p>}
          </>}
          {configured && <dl className="update-versions">
            <div><dt>{t("vps.update.versions.installed")}</dt><dd>{status!.release.installed!.active_release_version}</dd></div>
            <div><dt>{t("vps.update.versions.available")}</dt><dd>{verifiedVersion ?? t("vps.update.versions.notChecked")}</dd></div>
          </dl>}
          {(candidate || baseline) && <section className="update-review" aria-label={t("vps.update.review.label")}>
            <h3>{t("vps.update.review.title", { version: verifiedVersion ?? "" })}</h3>
            {releaseNotes && <p className="release-notes"><strong>{t(baseline || candidate?.action === "already_bound" ? "release.candidate.notes" : "release.candidate.whatsNew")}</strong> <span lang="en" dir="auto">{releaseNotes}</span></p>}
            <p>{candidate?.action === "already_bound" ? t("vps.update.review.alreadyInstalled") : baseline ? t("vps.update.review.baseline") : candidate?.baseline_required ? t("vps.update.review.register") : t("vps.update.review.upgrade")}</p>
            <dl className="result-facts"><div><dt>{t("vps.update.review.verification")}</dt><dd>{t("vps.update.review.verified")}</dd></div>
              <div><dt>{t("vps.update.review.compatibility")}</dt><dd>{baseline || candidate?.can_install || candidate?.action === "already_bound" ? t("vps.update.review.compatible") : t("vps.update.review.incompatible")}</dd></div>
              <div><dt>{t("vps.update.review.type")}</dt><dd>{(baseline?.security_update ?? candidate?.security_update) ? t("vps.update.review.security") : t("vps.update.review.standard")}</dd></div></dl>
            <SettingsDisclosure className="result-disclosure" summary={t("vps.common.softwareDetails")}>
              <p>{t("common.separator.pair", { first: formatTarget(baseline?.artifact.target ?? candidate?.artifact_target ?? ""), second: formatBytes(baseline?.artifact.size_bytes ?? candidate?.artifact_size_bytes ?? 0) })}</p>
              <HashValue label={t("vps.common.softwareHash")} value={baseline?.artifact.sha256 ?? candidate?.artifact_sha256 ?? ""} />
            </SettingsDisclosure>
          </section>}
          <fieldset className="ssh-operation-fields" disabled={working}>
            <section className="update-section">
              {!configured || editingSource || !source ? <>
                <Field label={t("vps.update.source.label")} hint={t("vps.update.source.help")} error={sourceError}>
                  <input type="url" value={sourceText} placeholder={t("vps.update.source.placeholder")} autoCapitalize="none" spellCheck={false} onChange={(event) => { setSource(event.target.value); typedSource.current = true; clearReview(); }} onBlur={() => setSource(source)} />
                </Field>
              </> : <div className="update-source-saved"><span>{t("vps.update.source.label")}</span><p>{source}</p><button type="button" className="text-button" onClick={() => setEditingSource(true)}>{t("vps.update.source.change")}</button></div>}
              <Field label={t("vps.update.channel.label")} hint={channel === "preview" ? t("vps.update.channel.previewHint") : undefined}>
                <select value={channel} onChange={(event) => { setChannel(event.target.value as typeof channel); clearReview(); }}><option value="stable">{t("vps.update.channel.stable")}</option><option value="preview">{t("vps.update.channel.preview")}</option></select>
              </Field>
            </section>
            {(configured || savedSchedule?.enabled) && <section className="update-section">
              <label className="preference-row">
                <span><strong>{t("vps.update.schedule.toggle")}</strong><small>{t("vps.update.schedule.help")}</small></span>
                <input type="checkbox" role="switch" checked={automatic}
                  disabled={!automatic && (!configured || !sourceValid)}
                  onChange={(event) => void saveSchedule(event.target.checked)} />
              </label>
              {sourceDiffers && <p className="settings-note">{t("vps.update.schedule.otherSource", { source: savedSchedule!.source! })}{" "}
                <button type="button" className="text-button" onClick={() => void saveSchedule(true)}>{t("vps.update.schedule.useSource")}</button></p>}
              {scheduleOutcome.kind === "failed" && <InlineError message={scheduleOutcome.message} onRetry={() => void saveSchedule(scheduleOutcome.requested)} retryDisabled={working} />}
              {scheduleOutcome.kind === "done" && <p className="update-saved" role="status"><Check size={16} weight="bold" />{scheduleOutcome.message}</p>}
            </section>}
            {status?.release.rollback_version && <section className="update-section">
              <h3>{t("vps.update.rollback.title")}</h3>
              <p className="settings-note">{t("vps.update.rollback.kept", { version: status.release.rollback_version })}</p>
              <button type="button" className="secondary-button" disabled={!disconnected} onClick={() => void rollback(status.release.rollback_version!)}>{t("vps.update.rollback.action", { version: status.release.rollback_version })}</button>
            </section>}
          </fieldset>
          <SettingsDisclosure className="result-disclosure" summary={t("vps.update.privacy.summary")}><p>{t("vps.update.privacy.identifiers")}</p><p>{t("vps.update.privacy.signing")}</p></SettingsDisclosure>
          <button type="button" className="text-button" disabled={working} onClick={op.back}>{t("vps.update.action.changeLogin")}</button>
        </div>}
      </DialogContent>
    </Dialog.Portal>
  </Dialog.Root>;
}
