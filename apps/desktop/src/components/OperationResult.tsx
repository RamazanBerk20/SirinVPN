import { t } from "../i18n";
import { ArrowClockwise, CheckCircle } from "@phosphor-icons/react";
import { useEffect, useRef, type ReactNode } from "react";

/** The outcome of a finished task. It is focused when it appears, so it is never below the fold. */
export function OperationResult({ title, children }: { title: string; children?: ReactNode }) {
  const result = useRef<HTMLElement>(null);
  useEffect(() => { result.current?.focus(); }, []);
  return <section className="operation-result" role="status" aria-label={t("app.operation.result")} tabIndex={-1} ref={result}>
    <span className="operation-result-icon"><CheckCircle size={28} weight="fill" /></span>
    <h3>{title}</h3>
    {children}
  </section>;
}

/** A task that is running: what it is doing, with one accurate line about waiting. */
export function OperationProgress({ title, note = t("vps.common.keepOpen") }: { title: string; note?: ReactNode }) {
  return <div className="operation-progress" role="status">
    <ArrowClockwise className="spin" size={28} />
    <strong>{title}</strong>
    {note && <p>{note}</p>}
  </div>;
}

/** The label for a pressed button while its task runs. */
export function Busy({ label }: { label: string }) {
  return <><ArrowClockwise className="spin" size={17} />{label}</>;
}
