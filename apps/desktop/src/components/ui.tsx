import { cloneElement, isValidElement, useId, type InputHTMLAttributes } from "react";
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
            aria-label={`${label} utilization`}
          />
        )}
      </div>
    </div>
  );
}

export function InlineError({ message }: { message: string }) {
  if (!message.trim()) return null;
  return (
    <div className="inline-error" role="alert">
      <Warning size={17} weight="fill" /> {message}
    </div>
  );
}

export function LoadingScreen() {
  return (
    <main className="loading-screen" role="status" aria-live="polite">
      <SirinMark className="brand-mark" />
      <p>Loading your VPN…</p>
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
        <p className="section-label">Safety boundary active</p>
        <h1>Protected controls are unavailable.</h1>
        <p className="initialization-summary">
          {message} No VPN or provisioning action was started.
        </p>
        <p>Unlock this device and check that its secure storage and SirinVPN system component are available. Your saved profiles are preserved.</p>
        {onRetry && <button className="primary-button" onClick={onRetry}>Retry initialization</button>}
        <button className="text-button" onClick={() => void navigator.clipboard.writeText("SirinVPN initialization failed. Protected controls are unavailable; no VPN or provisioning action was started.").catch(() => {})}>Copy diagnostic summary</button>
      </section>
    </main>
  );
}
