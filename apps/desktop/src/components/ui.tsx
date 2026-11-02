import { t } from "../i18n";
import { cloneElement, isValidElement, useEffect, useId, useRef, type InputHTMLAttributes } from "react";
import { Warning } from "@phosphor-icons/react";
import { Brand, SirinMark } from "./Brand";
import { SecretInput, SecretTextarea } from "./SecretInput";

export function Field({
  label,
  hint,
  error,
  children,
}: {
  label: string;
  hint?: string;
  error?: string;
  children: React.ReactNode;
}) {
  const id = useId();
  const secret = isValidElement(children) && (children.type === SecretInput || children.type === SecretTextarea);
  const control = isValidElement<InputHTMLAttributes<HTMLInputElement>>(children) && (secret || typeof children.type === "string" && ["input", "select", "textarea"].includes(children.type))
    ? cloneElement(children, { ...(secret ? { "aria-label": children.props["aria-label"] ?? label } : {}), "aria-invalid": Boolean(error) || children.props["aria-invalid"], "aria-describedby": [children.props["aria-describedby"], hint ? `${id}-hint` : null, error ? `${id}-error` : null].filter(Boolean).join(" ") || undefined }) : children;
  return (
    <label className="field">
      <span>{label}</span>
      {control}
      {hint ? <small id={`${id}-hint`}>{hint}</small> : null}
      {error && <small id={`${id}-error`} className="field-error" role="alert">{error}</small>}
    </label>
  );
}

export function Metric({
  label,
  value,
  icon,
  kind = "measurement",
  detail,
  percent,
}: {
  label: string;
  value: string;
  icon: React.ReactElement;
  kind?: "measurement" | "state";
  detail?: string;
  percent?: number;
}) {
  return (
    <div className="metric">
      <span>{icon}</span>
      <div>
        <small>{label}</small>
        <strong
          className={kind === "measurement" ? "metric-value" : "metric-state"}
        >
          {value}
        </strong>
        {detail && <span className="metric-detail">{detail}</span>}
        {percent !== undefined && Number.isFinite(percent) && (
          <meter
            min={0}
            max={100}
            value={Math.max(0, Math.min(100, percent))}
            aria-label={t("app.metric.usage", { label })}
          />
        )}
      </div>
    </div>
  );
}

/** A failure next to the control that caused it; it scrolls itself into view so it is never off screen. */
export function InlineError({ message, onRetry, retryLabel, retryDisabled }: { message: string; onRetry?: () => void; retryLabel?: string; retryDisabled?: boolean }) {
  const box = useRef<HTMLDivElement>(null);
  useEffect(() => { if (message.trim()) box.current?.scrollIntoView?.({ block: "nearest" }); }, [message]);
  if (!message.trim()) return null;
  return (
    <div className={`inline-error${onRetry ? " with-retry" : ""}`} role="alert" ref={box}>
      <Warning size={17} weight="fill" /> <span>{message}</span>
      {onRetry && <button type="button" className="secondary-button" disabled={retryDisabled} onClick={onRetry}>{retryLabel ?? t("common.action.retry")}</button>}
    </div>
  );
}

export function LoadingScreen() {
  return (
    <main className="loading-screen" role="status" aria-live="polite">
      <SirinMark className="brand-mark" />
      <p>{t("common.state.loading")}</p>
    </main>
  );
}

export function PlatformUnavailable({ message, onRetry }: { message: string; onRetry?: () => void }) {
  return (
    <main className="initialization-shell">
      <header className="initialization-brand">
        <Brand compact={false} />
      </header>
      <section
        className="initialization-card platform-unavailable"
        role="alert"
      >
        <Warning size={34} weight="duotone" />
        <h1>{t("app.unavailable.title")}</h1>
        <p className="initialization-summary">{message}</p>
        <p>{t("app.unavailable.help")}</p>
        {onRetry && <button className="primary-button" onClick={onRetry}>{t("common.action.retry")}</button>}
        <button className="text-button" onClick={() => void navigator.clipboard.writeText(t("app.unavailable.report", { message })).catch(() => {})}>{t("app.unavailable.copy")}</button>
      </section>
    </main>
  );
}
