import { useEffect, useRef, useState } from "react";
import { ArrowClockwise, Check, CheckCircle, Copy, Info, Warning } from "@phosphor-icons/react";
import type { DiagnosticCheck, DiagnosticReport } from "../types";
import { t } from "../i18n";
import { en } from "../i18n/en";
import { diagnosticCause } from "../lib/errors";
import { diagnosticEvidence, diagnosticGroup, groupDiagnostics } from "./diagnosticEvidence";
import { InlineError } from "./ui";
import { SettingsDisclosure, SettingsNotice } from "../features/settings/SettingsParts";
import { OperationProgress } from "./OperationResult";

const evidenceLabel = (check: DiagnosticCheck) => t(`maintenance.diagnostics.evidence.${diagnosticEvidence(check)}`);
const titles = en.maintenance.diagnostics.checkTitle;
type TitleCode = keyof typeof titles;

/** The check's name in the interface language, or null for a code this version doesn't know. */
export function checkTitle(code: string): string | null {
  if (Object.hasOwn(titles, code)) return t(`maintenance.diagnostics.checkTitle.${code as TitleCode}`);
  // Numbered DNS checks (dns_label in crates/core/src/diagnostics/remote.rs): indices are 0-based there, shown 1-based.
  const n = (value: string) => Number(value) + 1;
  let match = /^dns_(tls|https)_(\d+)$/.exec(code);
  if (match) return t(match[1] === "tls" ? "maintenance.diagnostics.numberedCheck.dnsTls" : "maintenance.diagnostics.numberedCheck.dnsHttps", { number: n(match[2]) });
  match = /^dns_zone_(\d+)(?:_(\d+))?$/.exec(code);
  if (match) return match[2] === undefined ? t("maintenance.diagnostics.numberedCheck.dnsZone", { zone: n(match[1]) })
    : t("maintenance.diagnostics.numberedCheck.dnsZoneUpstream", { zone: n(match[1]), upstream: n(match[2]) });
  return null;
}
// An unknown check keeps the backend's (English) label.
const checkLabel = (check: DiagnosticCheck) => checkTitle(check.code) ?? check.label;
const causeText = (check: DiagnosticCheck) => {
  const cause = diagnosticCause(check);
  return cause ? t(`maintenance.diagnostics.cause.${cause}`) : null;
};

export function diagnosticText(report: DiagnosticReport): string {
  return [t("maintenance.diagnostics.report.title"), t("maintenance.diagnostics.report.scope"), "",
    ...Object.values(groupDiagnostics(report.checks)).flat().map((check) => [
      t("maintenance.diagnostics.report.check", { level: t(`maintenance.diagnostics.report.level.${check.level}`), label: checkLabel(check) }),
      t("maintenance.diagnostics.report.evidence", { evidence: evidenceLabel(check) }),
      causeText(check),
      // The copied report is for support: the backend's own (English) message is kept verbatim.
      check.message,
    ].filter(Boolean).join("\n"))].join("\n\n");
}

/**
 * What a run checks while it runs. The VPS checks and leak tests only run while connected to this
 * server; all the checks run together and report at once, so every group spins until the report.
 */
export function DiagnosticProgress({ title, connected }: { title: string; connected: boolean }) {
  const groups = connected ? ["device", "identity", "server", "leaks"] as const : ["device", "identity"] as const;
  return <OperationProgress title={title} note={connected ? null : t("maintenance.diagnostics.progress.disconnected")}
    steps={groups.map((group) => ({ label: t(`maintenance.diagnostics.progress.${group}.label`), detail: t(`maintenance.diagnostics.progress.${group}.detail`), state: "running" }))} />;
}

/** An in-app fix for a check that didn't pass, keyed by the check's code. */
export type DiagnosticFixes = Partial<Record<string, { label: string; run: () => void }>>;

function DiagnosticRows({ checks, fixes = {} }: { checks: DiagnosticCheck[]; fixes?: DiagnosticFixes }) {
  return <div className="diagnostic-list">{checks.map((check) => {
    const group = diagnosticGroup(check);
    const fix = group !== "passed" ? fixes[check.code] : undefined;
    return <div key={check.code} className={`diagnostic-row ${check.level} ${group}`}>
      <span aria-label={t(`maintenance.diagnostics.group.${group}`)}>
        {group === "passed" ? <Check weight="bold" /> : group === "unavailable" ? <Info /> : <Warning weight="fill" />}
      </span>
      <div><strong lang={checkTitle(check.code) ? undefined : "en"} dir={checkTitle(check.code) ? undefined : "auto"}>{checkLabel(check)}</strong>
        {causeText(check) && <p>{causeText(check)}</p>}
        {/* The native diagnostics word their findings in English only: secondary detail under the translated name. */}
        <p className="error-detail" lang="en" dir="auto">{check.message}</p><span className="diagnostic-evidence">{evidenceLabel(check)}</span>
        {fix && <button type="button" className="secondary-button diagnostic-fix" onClick={fix.run}>{fix.label}</button>}</div>
    </div>;
  })}</div>;
}

/** A run that produced no report at all: no counters that could read as "all clear". */
export function DiagnosticRunFailed({ onRunAgain }: { onRunAgain?: () => void }) {
  return <InlineError message={t("maintenance.workspace.error.diagnostics")} onRetry={onRunAgain} retryLabel={t("settings.diagnostics.runAgain")} />;
}

export function DiagnosticResults({ report, onRunAgain, onConnect, fixes }: { report: DiagnosticReport; onRunAgain?: () => void; onConnect?: () => void; fixes?: DiagnosticFixes }) {
  const [copyState, setCopyState] = useState<"idle" | "copied" | "failed">("idle");
  const generation = useRef(0);
  useEffect(() => {
    generation.current += 1;
    setCopyState("idle");
    return () => { generation.current += 1; };
  }, [report]);
  // An empty run is not a result: no counters that could read as "all clear".
  if (!report.checks.length)
    // Nothing ran because nothing is connected: the next step is connecting, not another run.
    return <SettingsNotice action={onConnect ? { label: t("settings.parts.connect"), onClick: onConnect }
      : onRunAgain && { label: t("settings.diagnostics.runAgain"), onClick: onRunAgain }}>{t("settings.diagnostics.empty")}</SettingsNotice>;
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
        <DiagnosticRows checks={groups[group]} fixes={fixes} />
      </section>)}
      {groups.passed.length > 0 && <SettingsDisclosure className="diagnostic-passed" summary={t("maintenance.diagnostics.passedChecks", { count: groups.passed.length })}>
        <p className="settings-note">{t("maintenance.diagnostics.passedNote")}</p>
        <DiagnosticRows checks={groups.passed} />
      </SettingsDisclosure>}
    </div>
  </>;
}
