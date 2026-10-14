import { useEffect, useId, useRef, useState } from "react";
import * as Dialog from "@radix-ui/react-dialog";
import { DialogContent } from "../../components/DialogContent";
import { CopyValue } from "../../components/CopyValue";
import { Field, InlineError } from "../../components/ui";
import { api } from "../../api";
import { errorMessage } from "../../lib/errors";
import { t } from "../../i18n";
import { formatBytes } from "../../format";
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
      setSource(current.security_updates.source ?? rememberedReleaseSource(profile.id)); setAutomatic(current.security_updates.enabled);
      setChannel(current.release.installed?.channel ?? "stable");
      setStep("release");
    } catch (reason) { if (isCurrent(epoch)) setError(errorMessage(reason, t("vps.update.error.status"))); }
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
    } catch (reason) { if (isCurrent(epoch)) setError(errorMessage(reason, t("vps.common.error.unreachable"))); }
    finally { if (isCurrent(epoch)) setBusy(null); }
  }

  async function check() {
    const epoch = generation.current;
    if (!validReleaseSource(source)) return;
    setBusy(t("vps.update.busy.verifying")); setError(null); setMessage(null); setCandidate(null);
    try {
      const checked = await request<VpsReleaseCandidate>({ action: "check", source, channel });
      if (!isCurrent(epoch)) return;
      // An existing matching release can be registered without reinstalling it.
      // A different first release needs the separately reviewed guarded installer.
      if (!configured && !checked.can_install && checked.action !== "already_bound") {
        await prepareBaseline();
      } else { setCandidate(checked); rememberReleaseSource(profile.id, source); }
    }
    catch (reason) { if (isCurrent(epoch)) setError(errorMessage(reason, t("vps.update.error.check"))); }
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
        throw new Error(t("vps.update.error.notConfirmed"));
      await onCompleted();
      if (isCurrent(epoch)) setMessage(completed);
    } catch (reason) {
      // An interrupted transaction may now require recovery. Read it before
      // offering another install, without hiding the original failure.
      if (isCurrent(epoch)) {
        try { await loadStatus(); } catch { /* Keep the last known state and error. */ }
        if (isCurrent(epoch)) setError(errorMessage(reason, t("vps.update.error.stopped")));
      }
    }
    finally { if (isCurrent(epoch)) setBusy(null); }
  }

  async function saveSchedule() {
    const epoch = generation.current;
    const requested = automatic;
    const requestedSource = requested ? source : null;
    if (requested && !validReleaseSource(source)) return;
    setBusy(t("vps.update.busy.saving")); setScheduleError(null); setScheduleMessage(null);
    try {
      await request({ action: "configure", enabled: requested, source: requestedSource });
      const saved = await loadStatus();
      if (saved.security_updates.enabled !== requested ||
          (requested && saved.security_updates.source !== requestedSource))
        throw new Error(t("vps.update.error.scheduleNotConfirmed"));
      if (isCurrent(epoch)) setScheduleMessage(requested ? t("vps.update.schedule.enabled") : t("vps.update.schedule.disabled"));
    } catch (reason) { if (isCurrent(epoch)) setScheduleError(errorMessage(reason, t("vps.update.error.schedule"))); }
    finally { if (isCurrent(epoch)) setBusy(null); }
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
    setBusy(t("vps.update.busy.verifying")); setError(null); setMessage(null); setBaseline(null); setCandidate(null);
    try {
      const prepared = await api.prepareVpsBaseline({ ...await baselineAccess(), source, channel });
      if (isCurrent(epoch)) { setBaseline(prepared); rememberReleaseSource(profile.id, source); }
    }
    catch (reason) { if (isCurrent(epoch)) setError(errorMessage(reason, t("vps.update.error.check"))); }
    finally { if (isCurrent(epoch)) setBusy(null); }
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
    } catch (reason) { if (isCurrent(epoch)) setError(errorMessage(reason, t("vps.update.error.stopped"))); }
    finally { if (isCurrent(epoch)) setBusy(null); }
  }

  const verifiedVersion = baseline?.release_version ?? candidate?.release_version;
  const canFinish = Boolean(baseline || (candidate?.can_install && candidate.action !== "already_bound"));
  const clearReview = () => { setCandidate(null); setBaseline(null); setMessage(null); setScheduleMessage(null); };
  const finish = () => baseline ? installBaseline() : candidate ? perform(
    { action: "install", manifest_sha256: candidate.manifest_sha256 }, t("vps.update.busy.installing"),
    candidate.baseline_required ? t("vps.update.done.setUp", { version: candidate.release_version }) : t("vps.update.done.installed", { version: candidate.release_version }),
    candidate.release_version,
  ) : Promise.resolve();
  const primaryLabel = configured ? t("vps.update.action.install", { version: verifiedVersion ?? "" }) : baseline ? t("vps.update.action.installAndFinish") : t("vps.update.action.finishSetup");

  return <Dialog.Root open={open} onOpenChange={(next) => { if (!busy) onOpenChange(next); }}>
    <Dialog.Portal><Dialog.Overlay className="dialog-overlay" />
      <DialogContent className="dialog-content repair-server-dialog"
        heading={step === "release" && !configured ? t("vps.update.titleSetup", { name: profile.name }) : t("vps.update.title", { name: profile.name })}
        description={step === "release" ? configured ? t("vps.update.description.configured") : t("vps.update.description.setup") : t("vps.update.description.login")}
        closeDisabled={Boolean(busy)}
        footer={<>
          {busy ? <div className="workflow-progress" role="status"><strong>{busy}</strong><p>{t("vps.common.keepOpen")}</p></div> : <>
            <Dialog.Close asChild><button type="button" className="secondary-button">{step === "release" ? t("common.action.close") : t("common.action.cancel")}</button></Dialog.Close>
            {step === "login" && <button type="submit" form={loginFormId} className="primary-button" disabled={!login.valid}>{t("common.action.continue")}</button>}
            {step === "fingerprint" && <button className="primary-button" disabled={!confirmedHost} onClick={() => void accept()}>{t("common.action.continue")}</button>}
            {step === "release" && (canFinish
              ? <button className="primary-button" disabled={!disconnected || Boolean(status?.release.recovery_pending)} onClick={() => void finish()}>{primaryLabel}</button>
              : <button className="primary-button" disabled={!validReleaseSource(source) || Boolean(status?.release.recovery_pending)} onClick={() => void (status ? check() : prepareBaseline())}>{configured ? t("vps.update.action.check") : t("vps.update.action.verify")}</button>)}
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
            <ol className="setup-progress" aria-label={t("vps.update.steps.label")}>
              <li aria-current={!validReleaseSource(source) ? "step" : undefined} data-complete={validReleaseSource(source)}>{t("vps.update.steps.source")}</li>
              <li aria-current={validReleaseSource(source) && !canFinish ? "step" : undefined} data-complete={canFinish}>{t("vps.update.steps.verify")}</li>
              <li aria-current={canFinish ? "step" : undefined}>{t("vps.update.steps.finish")}</li>
            </ol>
            {!status && <p className="settings-note">{t("vps.update.statusUnknown")}</p>}
          </>}
          {configured && <dl className="update-versions">
            <div><dt>{t("vps.update.versions.installed")}</dt><dd>{status!.release.installed!.active_release_version}</dd></div>
            <div><dt>{t("vps.update.versions.available")}</dt><dd>{verifiedVersion ?? t("vps.update.versions.notChecked")}</dd></div>
          </dl>}
          {status?.release.installed && !status.installed_binary_matches && <InlineError message={t("vps.update.warning.mismatch")} />}
          {status?.automatic_outcome === "failed" && <InlineError message={t("vps.update.warning.automaticFailed")} />}
          {status?.release.recovery_pending && <div className="maintenance-prerequisite"><p>{t("vps.update.recovery.needed")}</p>
            <button className="secondary-button" disabled={Boolean(busy) || !disconnected} onClick={() => void perform({ action: "recover" }, t("vps.update.busy.recovering"), t("vps.update.done.recovered"))}>{t("vps.update.recovery.action")}</button>
          </div>}
          <fieldset className="ssh-operation-fields update-source" disabled={Boolean(busy)}>
            {!configured || editingSource || !source ? <>
              <Field label={t("vps.update.source.label")}><input type="url" aria-describedby={sourceHelpId} value={source} placeholder={t("vps.update.source.placeholder")} onChange={(event) => { setSource(event.target.value); clearReview(); }} /></Field>
              <p id={sourceHelpId} className="field-help">{t("vps.update.source.help")}</p>
            </> : <div className="update-source-saved"><span>{t("vps.update.source.label")}</span><p>{source}</p><button className="text-button" onClick={() => setEditingSource(true)}>{t("vps.update.source.change")}</button></div>}
            <Field label={t("vps.update.channel.label")}><select value={channel} onChange={(event) => { setChannel(event.target.value as typeof channel); clearReview(); }}><option value="stable">{t("vps.update.channel.stable")}</option><option value="preview">{t("vps.update.channel.preview")}</option></select></Field>
          </fieldset>
          {(candidate || baseline) && <section className="update-review" aria-label={t("vps.update.review.label")}>
            <h3>{t("vps.update.review.title", { version: verifiedVersion ?? "" })}</h3>
            <p>{candidate?.action === "already_bound" ? t("vps.update.review.alreadyInstalled") : baseline ? t("vps.update.review.baseline") : candidate?.baseline_required ? t("vps.update.review.register") : t("vps.update.review.upgrade")}</p>
              <dl className="result-facts"><div><dt>{t("vps.update.review.verification")}</dt><dd>{t("vps.update.review.verified")}</dd></div>
              <div><dt>{t("vps.update.review.compatibility")}</dt><dd>{baseline || candidate?.can_install || candidate?.action === "already_bound" ? t("vps.update.review.compatible") : t("vps.update.review.incompatible")}</dd></div>
              <div><dt>{t("vps.update.review.type")}</dt><dd>{(baseline?.security_update ?? candidate?.security_update) ? t("vps.update.review.security") : t("vps.update.review.standard")}</dd></div></dl>
            <details className="result-disclosure"><summary>{t("vps.common.softwareDetails")}</summary>
              <p>{t("common.separator.pair", { first: baseline?.artifact.target ?? candidate?.artifact_target ?? "", second: formatBytes(baseline?.artifact.size_bytes ?? candidate?.artifact_size_bytes ?? 0) })}</p>
              <div className="result-identity"><span>{t("vps.common.softwareHash")}</span><CopyValue label={t("vps.common.softwareHash")} value={baseline?.artifact.sha256 ?? candidate?.artifact_sha256 ?? ""} showCopyLabel /></div>
            </details>
          </section>}
          {(configured || status?.security_updates.enabled) && <section className="update-schedule">
            <h3>{t("vps.update.schedule.title")}</h3>
            <p className="schedule-state" role="status">{t("common.separator.pair", {
              first: status?.security_updates.enabled ? t("common.state.enabled") : t("common.state.disabled"),
              second: scheduleDirty ? t("vps.update.schedule.unsaved") : t("common.state.saved"),
            })}</p>
            <fieldset className="ssh-operation-fields" disabled={Boolean(busy)}>
              <label className="replacement-option"><input type="checkbox" checked={automatic} onChange={(event) => { setAutomatic(event.target.checked); setScheduleError(null); setScheduleMessage(null); }} /><span><strong>{t("vps.update.schedule.toggle")}</strong></span></label>
              <p className="field-help">{t("vps.update.schedule.help")}</p>
              <button className="secondary-button" disabled={!scheduleDirty || (automatic && (!configured || !validReleaseSource(source)))} onClick={() => void saveSchedule()}>{t("vps.update.schedule.save")}</button>
            </fieldset>
            {scheduleError && <InlineError message={scheduleError} />}
            {scheduleMessage && <p role="status">{scheduleMessage}</p>}
          </section>}
          {status?.release.rollback_version && <details className="result-disclosure"><summary>{t("vps.update.rollback.summary", { version: status.release.rollback_version })}</summary>
            <fieldset className="ssh-operation-fields" disabled={Boolean(busy)}><label className="replacement-option"><input type="checkbox" checked={rollbackConfirmed} onChange={(event) => setRollbackConfirmed(event.target.checked)} /><span><strong>{t("vps.update.rollback.confirm", { version: status.release.rollback_version })}</strong></span></label>
              <p className="field-help">{t("vps.update.rollback.help")}</p>
              <button className="secondary-button" disabled={!rollbackConfirmed || !disconnected} onClick={() => void perform({ action: "rollback", confirmed: true }, t("vps.update.busy.rollingBack"), t("vps.update.done.rolledBack", { version: status.release.rollback_version! }))}>{t("vps.update.rollback.action")}</button>
            </fieldset>
          </details>}
          <details className="result-disclosure"><summary>{t("vps.update.privacy.summary")}</summary><p>{t("vps.update.privacy.identifiers")}</p><p>{t("vps.update.privacy.signing")}</p></details>
          {!disconnected && <p className="field-help">{t("vps.update.disconnectFirst")}</p>}
          <button className="text-button" disabled={Boolean(busy)} onClick={() => setStep("login")}>{t("vps.update.action.changeLogin")}</button>
        </div>}
        {message && <p className="workflow-message" role="status">{message}</p>}
        {error && <InlineError message={error} />}
      </DialogContent>
    </Dialog.Portal>
  </Dialog.Root>;
}
