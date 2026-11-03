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
import { useSshLogin } from "../../hooks/useSshLogin";
import { useSshHostTrust, type InspectedSshHost } from "../../hooks/useSshHostTrust";
import { SshLoginFields } from "./SshLoginFields";
import { SshHostVerification } from "./SshHostVerification";
import type { ServerProfile } from "../../types";
import { completeReleaseSource, rememberedReleaseSource, rememberReleaseSource, validReleaseSource, type VpsBaselineCandidate, type VpsReleaseCandidate, type VpsReleaseOperation, type VpsReleaseStatus } from "./vpsRelease";

type Failure = { message: string; retry?: () => void };

export function VpsUpdateDialog({ profile, open, onOpenChange, disconnected, onCompleted, onRepair }: {
  profile: ServerProfile; open: boolean; onOpenChange: (value: boolean) => void;
  disconnected: boolean; onCompleted: () => Promise<void>;
  /** Opens repair for this VPS; offered when the installed software doesn't match its signed record. */
  onRepair?: () => void;
}) {
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
  const [sourceText, setSource] = useState("");
  // A folder address typed without its trailing "/" still counts; the field shows it once left.
  const source = completeReleaseSource(sourceText);
  const [editingSource, setEditingSource] = useState(false);
  const [channel, setChannel] = useState<"stable" | "preview">("stable");
  const [automatic, setAutomatic] = useState(false);
  const [busy, setBusy] = useState<string | null>(null);
  const [verifying, setVerifying] = useState(false);
  const [error, setError] = useState<Failure | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [scheduleError, setScheduleError] = useState<{ message: string; requested: boolean } | null>(null);
  const [scheduleMessage, setScheduleMessage] = useState<string | null>(null);
  const configured = Boolean(status?.release.installed);
  const mismatch = Boolean(status?.release.installed && !status.installed_binary_matches);
  const recoveryPending = Boolean(status?.release.recovery_pending);
  const savedSchedule = status?.security_updates;

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
      setChannel("stable"); setAutomatic(false); setVerifying(false);
      setBusy(null); setError(null); setMessage(null);
      setEditingSource(false); setScheduleError(null); setScheduleMessage(null);
  }, [open, profile.id]);

  const fail = (epoch: number, reason: unknown, fallback: string, retry?: () => void) => {
    if (isCurrent(epoch)) setError({ message: errorMessage(reason, fallback), retry });
  };

  async function request<T>(operation: VpsReleaseOperation, verified = fingerprint): Promise<T> {
    if (!verified) throw new Error(t("vps.update.error.notVerified"));
    const epoch = generation.current;
    if (!isCurrent(epoch)) throw new Error(t("vps.update.error.cancelled"));
    const credentials = await login.prepare(verified);
    if (!isCurrent(epoch)) throw new Error(t("vps.update.error.cancelled"));
    const result = await api.manageVpsRelease<T>({ server_id: profile.id,
      ssh: { host: profile.endpoint.host, ...credentials }, operation });
    if (!isCurrent(epoch)) throw new Error(t("vps.update.error.cancelled"));
    return result;
  }

  async function loadStatus(verified = fingerprint) {
    const current = await request<VpsReleaseStatus>({ action: "status" }, verified);
    setStatus(current);
    setAutomatic(current.security_updates.enabled);
    return current;
  }

  async function accept(checked: InspectedSshHost | null = trust.inspection) {
    const epoch = generation.current;
    if (!checked || (checked.status !== "trusted" && !confirmedHost)) return;
    setBusy(t("vps.update.busy.reading")); setError(null);
    try {
      const verified = await trust.accept(checked, confirmedHost);
      if (!isCurrent(epoch)) return;
      setFingerprint(verified);
      setStep("release");
      const current = await loadStatus(verified);
      setSource(current.security_updates.source ?? rememberedReleaseSource(profile.id));
      setChannel(current.release.installed?.channel ?? "stable");
    } catch (reason) { fail(epoch, reason, t("vps.update.error.status"), () => void accept(checked)); }
    finally { if (isCurrent(epoch)) setBusy(null); }
  }

  async function inspect() {
    const epoch = generation.current;
    if (!login.valid) return;
    setBusy(t("vps.update.busy.verifyingKey")); setError(null);
    try {
      const checked = await trust.inspect();
      if (!checked || !isCurrent(epoch)) return;
      if (checked.status === "trusted") await accept(checked);
      else { setConfirmedHost(false); setStep("fingerprint"); }
    } catch (reason) { fail(epoch, reason, t("vps.common.error.unreachable"), () => void inspect()); }
    finally { if (isCurrent(epoch)) setBusy(null); }
  }

  async function check() {
    const epoch = generation.current;
    if (!validReleaseSource(source)) return;
    setBusy(t("vps.update.busy.verifying")); setVerifying(true); setError(null); setMessage(null); setCandidate(null);
    try {
      const checked = await request<VpsReleaseCandidate>({ action: "check", source, channel });
      if (!isCurrent(epoch)) return;
      // An existing matching release can be registered without reinstalling it.
      // A different first release needs the separately reviewed guarded installer.
      if (!configured && !checked.can_install && checked.action !== "already_bound") {
        await prepareBaseline();
      } else { setCandidate(checked); rememberReleaseSource(profile.id, source); }
    }
    catch (reason) { fail(epoch, reason, t("vps.update.error.check"), () => void check()); }
    finally { if (isCurrent(epoch)) { setBusy(null); setVerifying(false); } }
  }

  async function perform(operation: VpsReleaseOperation, label: string, completed: string, expectedVersion?: string) {
    const epoch = generation.current;
    setBusy(label); setError(null); setMessage(null);
    try {
      await request(operation);
      setCandidate(null);
      const next = await loadStatus();
      if (expectedVersion && (next.release.installed?.active_release_version !== expectedVersion || !next.installed_binary_matches))
        throw new Error(t("vps.update.error.notConfirmed"));
      await onCompleted();
      if (isCurrent(epoch)) setMessage(completed);
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
    setBusy(t("vps.update.busy.saving")); setScheduleError(null); setScheduleMessage(null);
    try {
      await request({ action: "configure", enabled: requested, source: requestedSource });
      const saved = await loadStatus();
      read = true;
      if (saved.security_updates.enabled !== requested ||
          (requested && saved.security_updates.source !== requestedSource))
        throw new Error(t("vps.update.error.scheduleNotConfirmed"));
      if (isCurrent(epoch)) setScheduleMessage(requested ? t("vps.update.schedule.enabled") : t("vps.update.schedule.disabled"));
    } catch (reason) {
      // After a status read the switch already shows what the VPS saved.
      if (isCurrent(epoch)) {
        if (!read) setAutomatic(previous);
        setScheduleError({ message: errorMessage(reason, t("vps.update.error.schedule")), requested });
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

  async function baselineAccess() {
    if (!fingerprint) throw new Error(t("vps.update.error.notVerified"));
    const epoch = generation.current;
    const credentials = await login.prepare(fingerprint);
    if (!isCurrent(epoch)) throw new Error(t("vps.update.error.cancelled"));
    return { server_id: profile.id, ssh: { host: profile.endpoint.host, ...credentials } };
  }
  async function prepareBaseline() {
    const epoch = generation.current;
    if (!validReleaseSource(source)) return;
    setBusy(t("vps.update.busy.verifying")); setVerifying(true); setError(null); setMessage(null); setBaseline(null); setCandidate(null);
    try {
      const prepared = await api.prepareVpsBaseline({ ...await baselineAccess(), source, channel });
      if (isCurrent(epoch)) { setBaseline(prepared); rememberReleaseSource(profile.id, source); }
    }
    catch (reason) { fail(epoch, reason, t("vps.update.error.check"), () => void prepareBaseline()); }
    finally { if (isCurrent(epoch)) { setBusy(null); setVerifying(false); } }
  }
  async function installBaseline() {
    const epoch = generation.current;
    if (!baseline || !disconnected) return;
    setBusy(t("vps.update.busy.installingSetup")); setError(null); setMessage(null);
    try {
      await api.installVpsBaseline({ ...await baselineAccess(), manifest_sha256: baseline.manifest_sha256 });
      if (!isCurrent(epoch)) return;
      setBaseline(null); setCandidate(null);
      const next = await loadStatus();
      if (next.release.installed?.active_release_version !== baseline.release_version || !next.installed_binary_matches)
        throw new Error(t("vps.update.error.notConfirmed"));
      await onCompleted();
      if (isCurrent(epoch)) setMessage(t("vps.update.done.setUp", { version: baseline.release_version }));
    } catch (reason) { fail(epoch, reason, t("vps.update.error.stopped")); }
    finally { if (isCurrent(epoch)) setBusy(null); }
  }

  const verifiedVersion = baseline?.release_version ?? candidate?.release_version;
  const releaseNotes = baseline?.release_notes ?? candidate?.release_notes;
  const canFinish = Boolean(baseline || (candidate?.can_install && candidate.action !== "already_bound"));
  const sourceValid = validReleaseSource(source);
  const sourceError = source && !sourceValid ? t("vps.update.source.invalid") : undefined;
  const clearReview = () => { setCandidate(null); setBaseline(null); setMessage(null); setScheduleMessage(null); };
  const finish = () => baseline ? installBaseline() : candidate ? perform(
    // Finishing setup on the release already installed is not an update install.
    { action: "install", manifest_sha256: candidate.manifest_sha256 },
    t(configured ? "vps.update.busy.installing" : candidate.baseline_required ? "vps.update.busy.finishing" : "vps.update.busy.installingSetup"),
    candidate.baseline_required ? t("vps.update.done.setUp", { version: candidate.release_version }) : t("vps.update.done.installed", { version: candidate.release_version }),
    candidate.release_version,
  ) : Promise.resolve();
  const primaryLabel = configured ? t("vps.update.action.install", { version: verifiedVersion ?? "" }) : baseline ? t("vps.update.action.installAndFinish") : t("vps.update.action.finishSetup");
  // One reason beside the disabled primary action, most important first.
  const blocker = step === "login" ? login.missing
    : step === "fingerprint" ? (confirmedHost ? null : t("ssh.verify.confirmFirst"))
    : mismatch ? t("vps.update.blocked.mismatch")
    : recoveryPending ? t("vps.update.blocked.recovery")
    : canFinish ? (disconnected ? null : t("vps.update.disconnectFirst"))
    : sourceValid ? null : t("vps.update.blocked.source");
  const steps = [t("vps.update.steps.source"), t("vps.update.steps.verify"), t("vps.update.steps.finish")];
  const currentStep = canFinish ? 2 : verifying ? 1 : 0;
  const sourceDiffers = Boolean(savedSchedule?.enabled && savedSchedule.source && sourceValid && source !== savedSchedule.source);

  return <Dialog.Root open={open} onOpenChange={(next) => { if (!busy) onOpenChange(next); }}>
    <Dialog.Portal><Dialog.Overlay className="dialog-overlay" />
      <DialogContent className="dialog-content repair-server-dialog vps-update-dialog"
        heading={t("vps.update.title", { name: profile.name })}
        description={step === "release" ? configured ? t("vps.update.description.configured") : t("vps.update.description.setup") : t("vps.update.description.login")}
        closeDisabled={Boolean(busy)}
        footerNote={busy ? t("vps.common.keepOpen") : blocker}
        footer={<>
          {step === "fingerprint" && <DialogBack disabled={Boolean(busy)} onClick={() => setStep("login")} />}
          <Dialog.Close asChild><button type="button" className="secondary-button" disabled={Boolean(busy)}>{step === "release" ? t("common.action.close") : t("common.action.cancel")}</button></Dialog.Close>
          {busy ? <button type="button" className="primary-button" disabled><Busy label={busy} /></button> : <>
            {step === "login" && <button type="submit" form={loginFormId} className="primary-button" disabled={!login.valid}>{t("common.action.continue")}</button>}
            {step === "fingerprint" && <button type="button" className="primary-button" disabled={!confirmedHost} onClick={() => void accept()}>{t("common.action.continue")}</button>}
            {step === "release" && (canFinish
              ? <button type="button" className="primary-button" disabled={!disconnected || recoveryPending || mismatch} onClick={() => void finish()}>{primaryLabel}</button>
              : <button type="button" className="primary-button" disabled={!sourceValid || recoveryPending || mismatch} onClick={() => void (status ? check() : prepareBaseline())}>{configured ? t("vps.update.action.check") : t("vps.update.action.verify")}</button>)}
          </>}
        </>}>
        {error && <InlineError message={error.message} onRetry={error.retry} retryDisabled={Boolean(busy)} />}
        {step === "login" && <form id={loginFormId} className="uninstall-form" onSubmit={(event) => { event.preventDefault(); void inspect(); }}>
          <fieldset disabled={Boolean(busy)} className="ssh-operation-fields"><SshLoginFields login={login} /></fieldset>
        </form>}
        {step === "fingerprint" && trust.inspection && <fieldset disabled={Boolean(busy)} className="ssh-operation-fields">
          <SshHostVerification inspection={trust.inspection} confirmed={confirmedHost} onConfirmed={setConfirmedHost} />
        </fieldset>}
        {step === "release" && <div className="update-workflow">
          {message && <OperationResult title={message} />}
          {mismatch && <div className="update-blocker danger" role="alert">
            <Warning size={20} weight="fill" />
            <div><p>{t("vps.update.warning.mismatch")}</p>
              {onRepair && <button type="button" className="secondary-button" disabled={Boolean(busy)} onClick={onRepair}><Wrench size={17} />{t("vps.update.action.repair")}</button>}</div>
          </div>}
          {status?.automatic_outcome === "failed" && <div className="update-blocker"><Warning size={20} weight="fill" /><div><p>{t("vps.update.warning.automaticFailed")}</p></div></div>}
          {recoveryPending && <div className="update-blocker">
            <Warning size={20} weight="fill" />
            <div><p>{t("vps.update.recovery.needed")}</p>
              <button type="button" className="secondary-button" disabled={Boolean(busy) || !disconnected} onClick={() => void perform({ action: "recover" }, t("vps.update.busy.recovering"), t("vps.update.done.recovered"))}>{t("vps.update.recovery.action")}</button></div>
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
            {releaseNotes && <p><strong>{t("release.candidate.whatsNew")}</strong> {releaseNotes}</p>}
            <p>{candidate?.action === "already_bound" ? t("vps.update.review.alreadyInstalled") : baseline ? t("vps.update.review.baseline") : candidate?.baseline_required ? t("vps.update.review.register") : t("vps.update.review.upgrade")}</p>
            <dl className="result-facts"><div><dt>{t("vps.update.review.verification")}</dt><dd>{t("vps.update.review.verified")}</dd></div>
              <div><dt>{t("vps.update.review.compatibility")}</dt><dd>{baseline || candidate?.can_install || candidate?.action === "already_bound" ? t("vps.update.review.compatible") : t("vps.update.review.incompatible")}</dd></div>
              <div><dt>{t("vps.update.review.type")}</dt><dd>{(baseline?.security_update ?? candidate?.security_update) ? t("vps.update.review.security") : t("vps.update.review.standard")}</dd></div></dl>
            <details className="result-disclosure"><summary>{t("vps.common.softwareDetails")}</summary>
              <p>{t("common.separator.pair", { first: formatTarget(baseline?.artifact.target ?? candidate?.artifact_target ?? ""), second: formatBytes(baseline?.artifact.size_bytes ?? candidate?.artifact_size_bytes ?? 0) })}</p>
              <HashValue label={t("vps.common.softwareHash")} value={baseline?.artifact.sha256 ?? candidate?.artifact_sha256 ?? ""} />
            </details>
          </section>}
          <fieldset className="ssh-operation-fields" disabled={Boolean(busy)}>
            <section className="update-section">
              {!configured || editingSource || !source ? <>
                <Field label={t("vps.update.source.label")} hint={t("vps.update.source.help")} error={sourceError}>
                  <input type="url" value={sourceText} placeholder={t("vps.update.source.placeholder")} autoCapitalize="none" spellCheck={false} onChange={(event) => { setSource(event.target.value); clearReview(); }} onBlur={() => setSource(source)} />
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
              {scheduleError && <InlineError message={scheduleError.message} onRetry={() => void saveSchedule(scheduleError.requested)} retryDisabled={Boolean(busy)} />}
              {scheduleMessage && <p className="update-saved" role="status"><Check size={16} weight="bold" />{scheduleMessage}</p>}
            </section>}
            {status?.release.rollback_version && <section className="update-section">
              <h3>{t("vps.update.rollback.title")}</h3>
              <p className="settings-note">{t("vps.update.rollback.kept", { version: status.release.rollback_version })}</p>
              <button type="button" className="secondary-button" disabled={!disconnected} onClick={() => void rollback(status.release.rollback_version!)}>{t("vps.update.rollback.action", { version: status.release.rollback_version })}</button>
            </section>}
          </fieldset>
          <details className="result-disclosure"><summary>{t("vps.update.privacy.summary")}</summary><p>{t("vps.update.privacy.identifiers")}</p><p>{t("vps.update.privacy.signing")}</p></details>
          <button type="button" className="text-button" disabled={Boolean(busy)} onClick={() => setStep("login")}>{t("vps.update.action.changeLogin")}</button>
        </div>}
      </DialogContent>
    </Dialog.Portal>
  </Dialog.Root>;
}
