import { t } from "../i18n";
import { ArrowClockwise, Check, CheckCircle } from "@phosphor-icons/react";
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

/**
 * One step of a running task. The app only knows what it finished itself and which call is
 * running, so a call's stages are one running step, and checks that run together all spin.
 */
export type OperationStep = { label: string; state: "done" | "running" | "todo"; detail?: string };

/** The steps of a task that runs `labels` in order, with the one at `current` running. */
export const stepsAt = (labels: string[], current: number): OperationStep[] =>
  labels.map((label, index) => ({ label, state: index < current ? "done" : index === current ? "running" : "todo" }));

/** A task that is running: what it is doing, its steps when it has several, and one accurate line about waiting. */
export function OperationProgress({ title, note = t("vps.common.keepOpen"), steps }: { title: string; note?: ReactNode; steps?: OperationStep[] }) {
  return <div className={`operation-progress${steps ? " with-steps" : ""}`} role="status">
    {!steps && <ArrowClockwise className="spin" size={28} />}
    <strong>{title}</strong>
    {steps && <OperationSteps steps={steps} />}
    {note && <p>{note}</p>}
  </div>;
}

/** The step list on its own, for progress screens with their own layout. */
export function OperationSteps({ steps }: { steps: OperationStep[] }) {
  return <ol className="operation-steps">
    {steps.map((step) => <li key={step.label} data-state={step.state} aria-current={step.state === "running" ? "step" : undefined}>
      <span className="operation-step-mark" aria-hidden="true">
        {step.state === "done" ? <Check size={14} weight="bold" /> : step.state === "running" ? <ArrowClockwise className="spin" size={16} /> : null}
      </span>
      <span>
        {step.label}
        <span className="sr-only">{t(`app.operation.step.${step.state}`)}</span>
        {step.detail && <small>{step.detail}</small>}
      </span>
    </li>)}
  </ol>;
}

/** The label for a pressed button while its task runs. */
export function Busy({ label }: { label: string }) {
  return <><ArrowClockwise className="spin" size={17} />{label}</>;
}
