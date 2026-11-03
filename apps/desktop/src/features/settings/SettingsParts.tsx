import { CaretDown, Info, Warning } from "@phosphor-icons/react";
import type { ReactNode } from "react";
import { t } from "../../i18n";

type Action = { label: string; onClick: () => void; disabled?: boolean };

/** One readable notice inside a settings card, with the action that resolves it when the app has one. */
export function SettingsNotice({ tone = "info", action, children }: { tone?: "info" | "warning"; action?: Action; children: ReactNode }) {
  return <div className={`settings-notice ${tone}`}>
    {tone === "warning" ? <Warning size={18} weight="fill" /> : <Info size={18} />}
    <p>{children}</p>
    {action && <button type="button" className="secondary-button" disabled={action.disabled} onClick={action.onClick}>{action.label}</button>}
  </div>;
}

/** Cards that read the server say so once, with a Connect button where the page can connect. */
export function ConnectFirst({ onConnect }: { onConnect?: () => void }) {
  return <SettingsNotice action={onConnect && { label: t("settings.parts.connect"), onClick: onConnect }}>{t("common.error.needsConnection")}</SettingsNotice>;
}

/** A card's one save-state line: Discard and Save appear only while edits are unsaved. */
export function CardSaveRow({ dirty, saving, problem, saved, saveLabel, onSave, onDiscard, children }: {
  dirty: boolean;
  saving: boolean;
  /** Why Save is disabled, shown in place of "Unsaved changes". */
  problem?: string;
  /** The last save's result, shown until the next edit. */
  saved?: string | null;
  saveLabel: string;
  onSave: () => void;
  onDiscard: () => void;
  children?: ReactNode;
}) {
  const status = saving ? t("common.state.saving") : dirty ? problem || t("connection.saveBar.unsaved") : saved;
  return <div className={`card-save-row${dirty ? " is-dirty" : ""}`}>
    <p role="status" className={dirty && problem ? "field-error" : undefined}>{status}</p>
    {dirty ? <>
      <button type="button" className="text-button" disabled={saving} onClick={onDiscard}>{t("connection.saveBar.discard")}</button>
      <button type="button" className="primary-button" disabled={saving || Boolean(problem)} onClick={onSave}>{saveLabel}</button>
    </> : children}
  </div>;
}

/**
 * The one disclosure style in the app: a full-width row with a chevron. `boxed` draws it as its
 * own card where it stands alone in a form; `open` opens it initially.
 */
export function SettingsDisclosure({ summary, className, boxed, open, children }: { summary: ReactNode; className?: string; boxed?: boolean; open?: boolean; children: ReactNode }) {
  return <details className={`settings-disclosure${boxed ? " boxed" : ""}${className ? ` ${className}` : ""}`} open={open || undefined}>
    <summary>{summary}<CaretDown className="disclosure-chevron" size={17} aria-hidden /></summary>
    <div className="settings-disclosure-body">{children}</div>
  </details>;
}
