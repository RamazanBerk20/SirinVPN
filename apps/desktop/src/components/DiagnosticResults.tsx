import { useEffect, useRef, useState } from "react";
import { ArrowClockwise, Check, CheckCircle, Copy, Info, Warning } from "@phosphor-icons/react";
import type { DiagnosticCheck, DiagnosticReport } from "../types";
import { t } from "../i18n";
import { diagnosticEvidence, diagnosticGroup, groupDiagnostics } from "./diagnosticEvidence";
import { InlineError } from "./ui";
import { SettingsDisclosure, SettingsNotice } from "../features/settings/SettingsParts";

const evidenceLabel = (check: DiagnosticCheck) => t(`maintenance.diagnostics.evidence.${diagnosticEvidence(check)}`);
/** The workspace reports a run that never produced a report as this single synthetic check. */
const RUN_FAILED = "local_diagnostics_unavailable";

export function diagnosticText(report: DiagnosticReport): string {
  return [t("maintenance.diagnostics.report.title"), t("maintenance.diagnostics.report.scope"), "",
    ...Object.values(groupDiagnostics(report.checks)).flat().map((check) => [
      `[${check.level.toUpperCase()}] ${check.label}`,
      t("maintenance.diagnostics.report.evidence", { evidence: evidenceLabel(check) }),
      check.message,
    ].join("\n"))].join("\n\n");
}

function DiagnosticRows({ checks }: { checks: DiagnosticCheck[] }) {
  return <div className="diagnostic-list">{checks.map((check) => {
    const group = diagnosticGroup(check);
    return <div key={check.code} className={`diagnostic-row ${check.level} ${group}`}>
      <span aria-label={t(`maintenance.diagnostics.group.${group}`)}>
        {group === "passed" ? <Check weight="bold" /> : group === "unavailable" ? <Info /> : <Warning weight="fill" />}
      </span>
      <div><strong>{check.label}</strong><p>{check.message}</p><span className="diagnostic-evidence">{evidenceLabel(check)}</span></div>
    </div>;
  })}</div>;
}

export function DiagnosticResults({ report, onRunAgain }: { report: DiagnosticReport; onRunAgain?: () => void }) {
  const [copyState, setCopyState] = useState<"idle" | "copied" | "failed">("idle");
  const generation = useRef(0);
  useEffect(() => {
    generation.current += 1;
    setCopyState("idle");
    return () => { generation.current += 1; };
  }, [report]);
  // A failed run or an empty one is not a result: no counters that could read as "all clear".
  if (report.checks.length === 1 && report.checks[0].code === RUN_FAILED)
    return <InlineError message={report.checks[0].message} onRetry={onRunAgain} retryLabel={t("settings.diagnostics.runAgain")} />;
  if (!report.checks.length)
    return <SettingsNotice action={onRunAgain && { label: t("settings.diagnostics.runAgain"), onClick: onRunAgain }}>{t("settings.diagnostics.empty")}</SettingsNotice>;
  const copy = async () => {
    const request = generation.current;
    try {
      await navigator.clipboard.writeText(diagnosticText(report));
      if (request === generation.current) setCopyState("copied");
    } catch { if (request === generation.current) setCopyState("failed"); }
  };
  const groups = groupDiagnostics(report.checks);
  const counts = {
    attention: t("maintenance.diagnostics.summary.attention", { count: groups.attention.length }),
    review: t("maintenance.diagnostics.summary.review", { count: groups.review.length }),
    unavailable: t("maintenance.diagnostics.summary.unavailable", { count: groups.unavailable.length }),
    passed: t("maintenance.diagnostics.summary.passed", { count: groups.passed.length }),
  };
  const allPassed = groups.passed.length === report.checks.length;
  return <>
    {allPassed && <p className="diagnostic-headline"><CheckCircle size={22} weight="fill" />{t("settings.diagnostics.allPassed", { count: groups.passed.length })}</p>}
    <div className="diagnostic-summary">
      <p role="status">{groups.unavailable.length > 0 ? t("maintenance.diagnostics.summary.withUnavailable", counts) : t("maintenance.diagnostics.summary.line", counts)}</p>
      <div className="diagnostic-summary-actions">
        {onRunAgain && <button className="text-button" type="button" onClick={onRunAgain}><ArrowClockwise size={16} />{t("settings.diagnostics.runAgain")}</button>}
        <button className="text-button" type="button" onClick={() => void copy()}><Copy size={16} />{t("maintenance.diagnostics.copy")}</button>
      </div>
      {copyState !== "idle" && <p className="settings-note" role="status">{copyState === "copied" ? t("maintenance.diagnostics.copied") : t("maintenance.diagnostics.copyFailed")}</p>}
    </div>
    <div className="diagnostic-groups">
      {(["attention", "review", "unavailable"] as const).map((group) => groups[group].length > 0 && <section key={group} className="diagnostic-group">
        <h3>{t(`maintenance.diagnostics.group.${group}`)}</h3>
        <DiagnosticRows checks={groups[group]} />
      </section>)}
      {groups.passed.length > 0 && <SettingsDisclosure className="diagnostic-passed" summary={t("maintenance.diagnostics.passedChecks", { count: groups.passed.length })}>
        <p className="settings-note">{t("maintenance.diagnostics.passedNote")}</p>
        <DiagnosticRows checks={groups.passed} />
      </SettingsDisclosure>}
    </div>
  </>;
}
