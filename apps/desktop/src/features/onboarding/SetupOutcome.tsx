import { ArrowLeft, ArrowClockwise, Check, Key, ShieldCheck, Warning } from "@phosphor-icons/react";
import { CopyButton } from "../../components/CopyButton";
import { OperationSteps } from "../../components/OperationResult";
import { InlineError } from "../../components/ui";
import { t } from "../../i18n";
import { isAndroid } from "../../platform";
import type { ProvisionResult } from "../../types";
import { ServerNetworkPreflight } from "../settings/ServerNetworkPreflight";

export type InstallStage = "connect" | "check" | "upload" | "configure";
/** What a failed install left on the server: nothing, changes the installer rolled back, or not known. */
export type ServerChange = "unchanged" | "rolledBack" | "unknown";

// The installer reports "server transaction failed during <phase>: …" (crates/installer); it
// rolls back from "server configuration" on, and earlier phases only use a temporary directory.
const phases: Record<string, InstallStage> = {
  connection: "connect", "host key": "connect",
  discovery: "check", "network preflight": "check", "existing installation inspection": "check", "existing authorization inspection": "check",
  staging: "upload", artifact: "upload", "artifact upload": "upload", "owner identity upload": "upload", "artifact verification": "upload", "installer upload": "upload",
  "server configuration": "configure", "owner enrollment": "configure", "operational configuration": "configure", "health verification": "configure", commit: "configure",
};
// Installer errors raised before anything is written to the server.
const early: [RegExp, InstallStage][] = [
  [/SSH host key|SSH authentication failed/i, "connect"],
  [/server is incompatible|already installed with a different/i, "check"],
];

export function describeInstallFailure(message: string): { stage: InstallStage | null; change: ServerChange } {
  const phase = /failed during ([a-z ]+):/.exec(message)?.[1];
  const stage = phase ? phases[phase] : early.find(([pattern]) => pattern.test(message))?.[1];
  if (!stage) return { stage: null, change: "unknown" };
  return { stage, change: stage === "configure" ? "rolledBack" : "unchanged" };
}

/** Back to the previous setup step; on Android the app bar's arrow already leaves the flow. */
export function StepBack({ onClick, disabled }: { onClick: () => void; disabled?: boolean }) {
  return <button type="button" className="text-button flow-back" disabled={disabled} onClick={onClick}>
    <ArrowLeft size={16} aria-hidden="true" /> {t(isAndroid ? "onboarding.setup.previousStep" : "common.action.back")}
  </button>;
}

const stepKeys = ["onboarding.setup.progress.server", "onboarding.setup.progress.verify", "onboarding.setup.progress.install"] as const;

/** Where the user is in the three setup steps. */
export function SetupProgress({ current }: { current: 0 | 1 | 2 }) {
  return <ol className="setup-steps" aria-label={t("onboarding.setup.progress.label")}>
    {stepKeys.map((key, index) => <li key={key} className={index < current ? "done" : index === current ? "current" : ""} aria-current={index === current ? "step" : undefined}>
      <span aria-hidden="true">{index < current ? <Check size={12} weight="bold" /> : index + 1}</span>{t(key)}
    </li>)}
  </ol>;
}

export function InstallProgress({ host, steps }: { host: string; steps: boolean }) {
  return <div className="install-state" aria-live="polite">
    {steps && <SetupProgress current={2} />}
    <div className="install-orbit"><ShieldCheck size={32} weight="duotone" /></div>
    <h2>{t("onboarding.setup.installing.title")}</h2>
    <p>{t("onboarding.setup.installing.summary", { host })}</p>
    {/* The installer reports no stages while it runs, so its stages are one running step. */}
    <OperationSteps steps={[
      { label: t("onboarding.setup.installing.stepChecked"), state: "done" },
      { label: t("onboarding.setup.installing.stepInstall"), detail: t("onboarding.setup.installing.stepInstallDetail"), state: "running" },
    ]} />
    <p className="install-keep-open">{t("onboarding.setup.installing.keepOpen")}</p>
  </div>;
}

/** A failed install stays on the install step: what stopped, what it left on the server, and both ways on. */
export function InstallFailure({ error, fingerprint, steps, canRetry, onRetry, onBack }: {
  error: string; fingerprint: string; steps: boolean; canRetry: boolean; onRetry: () => void; onBack: () => void;
}) {
  const { stage, change } = describeInstallFailure(error);
  return <div className="install-failure">
    {steps && <SetupProgress current={2} />}
    <span className="install-failure-icon"><Warning size={28} weight="fill" /></span>
    <h2>{t("onboarding.setup.failed.title")}</h2>
    <dl className="install-failure-facts">
      {stage && <div><dt>{t("onboarding.setup.failed.stage")}</dt><dd>{t(`onboarding.setup.failed.stages.${stage}`)}</dd></div>}
      <div><dt>{t("onboarding.setup.failed.server")}</dt><dd>{t(`onboarding.setup.failed.change.${change}`)}</dd></div>
      <div><dt>{t("onboarding.setup.failed.fingerprint")}</dt><dd><code>{fingerprint}</code></dd></div>
    </dl>
    <InlineError message={error} />
    {!canRetry && <p className="settings-note">{t("onboarding.setup.failed.signInAgain")}</p>}
    <div className="install-failure-actions">
      <button type="button" className="secondary-button" onClick={onBack}>{t("onboarding.setup.failed.back")}</button>
      {canRetry && <button type="button" className="primary-button" onClick={onRetry}><ArrowClockwise size={17} />{t("onboarding.setup.failed.retry")}</button>}
    </div>
  </div>;
}

export function InstallSuccess({ result, onOpen, onRecoveryKey }: {
  result: ProvisionResult; onOpen: () => void; onRecoveryKey: () => void;
}) {
  return <div className="success-state install-success">
    <span className="success-icon"><Check size={28} weight="bold" /></span>
    <h2>{t("onboarding.setup.success.title")}</h2>
    <p>{t("onboarding.setup.success.summary", { name: result.profile.name })}</p>
    <section className="recovery-prompt" aria-label={t("onboarding.setup.success.recoveryTitle")}>
      <Key size={22} weight="duotone" aria-hidden="true" />
      <div><strong>{t("onboarding.setup.success.recoveryTitle")}</strong><p>{t("onboarding.setup.success.recoverySummary")}</p></div>
    </section>
    {result.network_preflight && <ServerNetworkPreflight report={result.network_preflight} />}
    <div className="install-success-actions">
      <button type="button" className="secondary-button" onClick={onRecoveryKey}><Key size={17} />{t("onboarding.setup.success.recoveryKey")}</button>
      <button type="button" className="primary-button" onClick={onOpen}>{t("onboarding.setup.success.open")}</button>
    </div>
  </div>;
}

/** The pinned or verified SSH key with a copy button. */
export function FingerprintValue({ value }: { value: string }) {
  return <div className="fingerprint-value"><code>{value}</code><CopyButton value={value} label={t("onboarding.setup.fingerprint.copy")} /></div>;
}
