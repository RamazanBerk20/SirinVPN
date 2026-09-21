import { useEffect, useRef, useState } from "react";
import { Check, Copy, Info, Warning } from "@phosphor-icons/react";
import type { DiagnosticCheck, DiagnosticReport } from "../types";
import { diagnosticEvidence, diagnosticGroup, groupDiagnostics } from "./diagnosticEvidence";

export function diagnosticText(report: DiagnosticReport): string {
  return ["SirinVPN — current diagnostics", "Current observations only; no activity history.", "",
    ...Object.values(groupDiagnostics(report.checks)).flat().map((check) => `[${check.level.toUpperCase()}] ${check.label}\nEvidence: ${diagnosticEvidence(check)}\n${check.message}`)].join("\n\n");
}

function DiagnosticRows({ checks }: { checks: DiagnosticCheck[] }) {
  return <div className="diagnostic-list">{checks.map((check) => {
    const group = diagnosticGroup(check);
    return <div key={check.code} className={`diagnostic-row ${check.level} ${group}`}>
      <span aria-label={group === "passed" ? "Passed" : group === "attention" ? "Needs attention" : group === "unavailable" ? "Not checked" : "Review"}>
        {group === "passed" ? <Check weight="bold" /> : group === "unavailable" ? <Info /> : <Warning weight="fill" />}
      </span>
      <div><strong>{check.label}</strong><p>{check.message}</p><span className="diagnostic-evidence">{diagnosticEvidence(check)}</span></div>
    </div>;
  })}</div>;
}

export function DiagnosticResults({ report }: { report: DiagnosticReport }) {
  const [copyState, setCopyState] = useState<"idle" | "copied" | "failed">("idle");
  const generation = useRef(0);
  useEffect(() => {
    generation.current += 1;
    setCopyState("idle");
    return () => { generation.current += 1; };
  }, [report]);
  const copy = async () => {
    const request = generation.current;
    try {
      await navigator.clipboard.writeText(diagnosticText(report));
      if (request === generation.current) setCopyState("copied");
    } catch { if (request === generation.current) setCopyState("failed"); }
  };
  const groups = groupDiagnostics(report.checks);
  return <>
    <div className="diagnostic-summary">
      <p role="status">{groups.attention.length} need attention · {groups.review.length} to review{groups.unavailable.length > 0 ? ` · ${groups.unavailable.length} not checked` : ""} · {groups.passed.length} passed</p>
      <button className="text-button" type="button" onClick={() => void copy()}><Copy size={16} />Copy sanitized report</button>
      {copyState !== "idle" && <p className="settings-note" role="status">{copyState === "copied" ? "Report copied. It remains in your clipboard until replaced or cleared." : "The report could not be copied. Check clipboard access and try again."}</p>}
    </div>
    <div className="diagnostic-groups">
      {(["attention", "review", "unavailable"] as const).map((group) => groups[group].length > 0 && <section key={group} className="diagnostic-group">
        <h3>{group === "attention" ? "Needs attention" : group === "review" ? "Review" : "Not checked / unavailable"} <span>{groups[group].length}</span></h3>
        <DiagnosticRows checks={groups[group]} />
      </section>)}
      {groups.passed.length > 0 && <details className="diagnostic-passed"><summary>Passed checks · {groups.passed.length}</summary>
        <p className="settings-note">These checks establish the conditions described below. Service reports and configuration checks do not test every traffic-leak scenario.</p>
        <DiagnosticRows checks={groups.passed} />
      </details>}
    </div>
  </>;
}
