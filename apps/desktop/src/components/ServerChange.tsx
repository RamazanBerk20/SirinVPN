import { useState } from "react";
import { api, type InstallPlan } from "../api";
import { t } from "../i18n";
import { appError, errorMessage, MAINTENANCE_BLOCKERS } from "../lib/errors";
import { SettingsDisclosure, SettingsNotice } from "../features/settings/SettingsParts";
import { Busy } from "./OperationResult";
import { InlineError } from "./ui";

/** "Show what will be done": the dry run of an Owner server change, loaded each time it opens. */
export function OperationPlan({ load }: { load: () => Promise<InstallPlan> }) {
  const [plan, setPlan] = useState<InstallPlan | "loading" | { error: string } | null>(null);
  const open = async () => {
    setPlan("loading");
    try { setPlan(await load()); } catch (reason) { setPlan({ error: errorMessage(reason, t("vps.change.plan.error")) }); }
  };
  return <SettingsDisclosure className="operation-plan" summary={t("vps.change.plan.show")} onToggle={(opened) => { if (opened) void open(); }}>
    {plan === "loading" || plan === null ? <p role="status"><Busy label={t("vps.change.plan.loading")} /></p>
      : "error" in plan ? <InlineError message={plan.error} />
      : <>
        <h4>{t("vps.change.plan.commands")}</h4>
        <ol className="operation-plan-steps">{plan.steps.map((step, index) => <li key={index}>
          {step.kind === "run" ? <><code>{step.command}</code>{step.privileged && <small> {t("vps.change.plan.asRoot")}</small>}</>
            : step.kind === "upload" ? t("vps.change.plan.upload", { path: step.path, mode: step.mode })
            : step.description}
        </li>)}</ol>
        {plan.managed_paths.length > 0 && <>
          <h4>{t("vps.change.plan.files")}</h4>
          <ul className="operation-plan-files">{plan.managed_paths.map((path) => <li key={path}><code>/{path}</code></li>)}</ul>
        </>}
      </>}
  </SettingsDisclosure>;
}

/**
 * Asks the VPS how a change whose confirmation was lost ended, with the saved login, or forgets it
 * after a confirmation (the server may be in either state; keys are kept). `message` replaces the
 * default explanation, e.g. for an earlier change that blocks a new one.
 */
export function CheckChangeAgain({ host, message, onResolved }: { host: string; message?: string; onResolved?: () => void }) {
  type State = "unknown" | "checking" | "confirmForget" | "forgetting" | "committed" | "rolledBack" | "forgotten" | { error: string };
  const [state, setState] = useState<State>("unknown");
  const busy = state === "checking" || state === "forgetting";
  const check = async () => {
    setState("checking");
    try {
      const resolved = await api.resolveInstallTransaction({}, host || undefined);
      setState(resolved?.state === "rolled_back" ? "rolledBack" : "committed");
      onResolved?.();
    } catch (reason) {
      setState({ error: errorMessage(reason, t("vps.change.unknown.checkFailed")) });
    }
  };
  const forget = async () => {
    setState("forgetting");
    try {
      await api.abandonInstallTransaction(host);
      setState("forgotten");
      onResolved?.();
    } catch (reason) {
      setState({ error: errorMessage(reason, t("vps.change.unknown.forgetFailed")) });
    }
  };
  if (state === "committed") return <SettingsNotice>{t("vps.change.unknown.committed", { host })}</SettingsNotice>;
  if (state === "rolledBack") return <SettingsNotice>{t("vps.change.rolledBack")}</SettingsNotice>;
  if (state === "forgotten") return <SettingsNotice tone="warning">{t("vps.change.unknown.forgotten", { host })}</SettingsNotice>;
  if (state === "confirmForget" || state === "forgetting") return <div className="settings-notice warning" role="alertdialog" aria-labelledby="forget-change-title">
    <div>
      <strong id="forget-change-title">{t("vps.change.unknown.forgetTitle", { host })}</strong>
      <p>{t("vps.change.unknown.forgetMessage")}</p>
    </div>
    <div className="settings-action-row">
      <button type="button" className="secondary-button" disabled={busy} onClick={() => setState("unknown")}>{t("common.action.cancel")}</button>
      <button type="button" className="primary-button danger-action" disabled={busy} onClick={() => void forget()}>
        {state === "forgetting" ? t("vps.change.unknown.forgetting") : t("vps.change.unknown.forgetConfirm")}
      </button>
    </div>
  </div>;
  return <>
    <SettingsNotice tone="warning" action={{ label: state === "checking" ? t("vps.change.unknown.checking") : t("vps.change.unknown.checkAgain"), disabled: busy, onClick: () => void check() }}>
      {message ?? t("vps.change.unknown.message", { host })}
    </SettingsNotice>
    {host && <button type="button" className="secondary-button" disabled={busy} onClick={() => setState("confirmForget")}>{t("vps.change.unknown.forget")}</button>}
    {typeof state === "object" && <InlineError message={state.error} />}
  </>;
}

/**
 * The failure of an Owner server change: an unknown outcome can be checked again, a rollback says
 * nothing changed, and blocked maintenance lists each reason. Anything else is `message`.
 */
export function ServerChangeFailure({ reason, message, onResolved }: { reason: unknown; message: string | null; onResolved?: () => void }) {
  const failure = appError(reason, ["install_outcome_unknown", "transaction_unresolved", "install_rolled_back", "maintenance_blocked"]);
  const blockers = Array.isArray(failure.params.blockers) ? failure.params.blockers as string[] : [];
  const english = Array.isArray(failure.params.messages) ? failure.params.messages as string[] : [];
  if (failure.code === "install_outcome_unknown") return <CheckChangeAgain host={String(failure.params.host ?? "")} onResolved={onResolved} />;
  // An earlier change on this server blocks a new one: the same two ways out.
  if (failure.code === "transaction_unresolved") {
    const host = String(failure.params.host ?? "");
    return <CheckChangeAgain host={host} message={t("common.errorCode.transaction_unresolved", { host })} onResolved={onResolved} />;
  }
  if (failure.code === "install_rolled_back") return <SettingsNotice>{t("vps.change.rolledBack")}</SettingsNotice>;
  if (failure.code === "maintenance_blocked" && blockers.length > 0) return <div className="inline-error" role="alert">
    <span>{t("vps.change.blocked")}</span>
    {/* A blocker this version doesn't know keeps the backend's English sentence. */}
    <ul>{blockers.map((blocker, index) => (MAINTENANCE_BLOCKERS as readonly string[]).includes(blocker)
      ? <li key={blocker}>{t(`common.maintenanceBlocker.${blocker as typeof MAINTENANCE_BLOCKERS[number]}`)}</li>
      : <li key={blocker} lang="en" dir="auto">{english[index] ?? blocker}</li>)}</ul>
  </div>;
  return message ? <InlineError message={message} /> : null;
}
