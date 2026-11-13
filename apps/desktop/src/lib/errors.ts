import { formatDateTime, formatList, t } from "../i18n";
import type { DiagnosticCheck } from "../types";

/**
 * Every backend error the UI branches on, as a stable code (sent by src-tauri/src/command_error.rs,
 * src-tauri/src/vps_transaction.rs and crates/android-runtime). The UI never matches backend text
 * anywhere else: it calls `appError` (errors) or `diagnosticCause` (diagnostic checks) and switches
 * on `code`. `detail` is the backend's own text, always kept for display. Each code has its text in
 * `common.errorCode.<code>`; errorCodes.test.ts checks this list against the Rust sources.
 */
export const ERROR_CODES = [
  /** Hetzner may have created the server; `params.server` is its name. */
  "hetzner_create_uncertain",
  /** Android: an earlier Hetzner server (`params.name`) was not finished. */
  "hetzner_provision_pending",
  /** Android: the new Hetzner server (`params.name`) presented a different host key than the pre-seeded one. */
  "hetzner_host_key_replacement",
  /** The installer stopped in a named phase; `params.phase` is the installer's (English) phase name. */
  "install_phase_failed",
  /** The installer failed to sign in over SSH (host key or authentication), before writing anything. */
  "install_ssh_failed",
  /** The server is incompatible or runs another installation, found before writing anything. */
  "install_incompatible",
  "backup_wrong_password",
  "invitation_expired",
  "invitation_used",
  "invitation_invalid",
  /** A port-forward failure caused by the public port (reserved, taken or invalid). */
  "port_forward_public_port",
  /** Another change to this server is running; wait for it, then try again. */
  "operation_in_progress",
  /** Owner maintenance can't start; `params.blockers` names each blocker (MAINTENANCE_BLOCKERS) and `params.messages` says it in English. */
  "maintenance_blocked",
  /** A server change's commit reply was lost; `params.host` names the VPS and `params.reason` (English) why the outcome is unknown. */
  "install_outcome_unknown",
  /** The VPS rolled a server change back, so nothing changed. */
  "install_rolled_back",
  /** An earlier change to `params.host` from this device is unresolved; resolve it before starting another. */
  "transaction_unresolved",
  /** The person still has device join codes. */
  "person_has_join_codes",
  /** Another person on the server already has this name. */
  "person_name_taken",
] as const;
export type ErrorCode = typeof ERROR_CODES[number] | "unknown";

/** `MaintenanceBlocker` in crates/installer/src/owner_maintenance.rs, serialized snake_case. */
export const MAINTENANCE_BLOCKERS = ["not_owner", "connected", "persistent_policy", "pending_key_rotation", "unresolved_transaction"] as const;

export interface AppError {
  code: ErrorCode;
  /** String values, or string lists (`maintenance_blocked`). */
  params: Readonly<Record<string, string | readonly string[]>>;
  /** The backend's text, shown to the user in every locale. */
  detail: string;
}

/** Causes a diagnostic check names (`caused(...)` in crates/core/src/diagnostics). Each has `maintenance.diagnostics.cause.<cause>`. */
export const DIAGNOSTIC_CAUSES = ["not_measured", "mtu_pending", "management_clock", "management_credentials_invalid",
  "management_device_rejected", "management_access_rejected", "management_unreachable"] as const;
export type DiagnosticCause = typeof DIAGNOSTIC_CAUSES[number] | null;

const codes = new Set<string>(ERROR_CODES);
/** Codes whose catalog text says everything the backend's text does, so no detail is shown under it. */
const complete = new Set<ErrorCode>(["backup_wrong_password", "invitation_expired", "invitation_used", "invitation_invalid",
  "operation_in_progress", "install_rolled_back", "transaction_unresolved", "maintenance_blocked", "hetzner_create_uncertain", "hetzner_provision_pending"]);

function detailOf(reason: unknown): string {
  if (typeof reason === "string") return reason.trim();
  if (reason instanceof Error) return reason.message.trim();
  if (reason && typeof reason === "object" && typeof (reason as { message?: unknown }).message === "string") return (reason as { message: string }).message.trim();
  return "";
}

/** Maps any rejection from `invoke` to a typed error. `only` lists the codes this caller handles; any other is `unknown`. */
export function appError(reason: unknown, only?: readonly ErrorCode[]): AppError {
  const detail = detailOf(reason);
  const structured = reason && typeof reason === "object" ? reason as { code?: unknown; params?: unknown } : null;
  const code = structured?.code as ErrorCode;
  if (typeof code === "string" && codes.has(code) && (!only || only.includes(code))) {
    const params = structured!.params && typeof structured!.params === "object" ? structured!.params as AppError["params"] : {};
    return { code, params, detail };
  }
  return { code: "unknown", params: {}, detail };
}

/** The cause a diagnostic check names, or null when it names none (or comes from an older server). */
export function diagnosticCause(check: DiagnosticCheck): DiagnosticCause {
  return (DIAGNOSTIC_CAUSES as readonly unknown[]).includes(check.cause) ? check.cause! : null;
}

/** The translated text of a coded error, in the interface language. */
export function errorCodeText(error: AppError): string {
  const text = (name: string) => typeof error.params[name] === "string" ? error.params[name] as string : "";
  switch (error.code) {
    case "unknown": return "";
    case "maintenance_blocked": {
      const blockers = Array.isArray(error.params.blockers) ? error.params.blockers as string[] : [];
      const steps = blockers.filter((blocker): blocker is typeof MAINTENANCE_BLOCKERS[number] => (MAINTENANCE_BLOCKERS as readonly string[]).includes(blocker))
        .map((blocker) => t(`common.maintenanceBlocker.${blocker}`));
      return steps.length ? t("common.errorCode.maintenance_blocked", { steps: formatList(steps) }) : t("common.errorCode.maintenance_blocked_unnamed");
    }
    // Android names the server `name`, the desktop `server`.
    case "hetzner_create_uncertain": return t("common.errorCode.hetzner_create_uncertain", { server: text("server") || text("name") });
    default: return t(`common.errorCode.${error.code}`, { name: text("name"), host: text("host") });
  }
}

/** A failure for display: the translated summary, and the backend's own (English) text as secondary detail. */
export interface ErrorDescription { summary: string; detail: string }

/**
 * The caller's localized summary of what failed (its first sentence, plus the code's own text for a
 * coded error), and the backend's cause. The cause is kept in every locale (it may be the only advice
 * there is, e.g. "check the Hetzner Console"), but only ever as detail under translated text.
 */
export function describeError(reason: unknown, fallback: string): ErrorDescription {
  let detail = detailOf(reason);
  if (!detail) return { summary: fallback, detail: "" };
  // Only the first sentence names the action; any advice after it would repeat the cause's own.
  const action = fallback.trim().match(/^.*?[.!?。！？؟](?=\s|$)/)?.[0] ?? fallback.trim();
  const coded = appError(reason);
  const cause = errorCodeText(coded);
  const summary = cause ? t("common.error.withDetail", { summary: action, detail: cause }) : action;
  // The catalog says all these codes' backend text says; any other detail is kept.
  if (complete.has(coded.code)) return { summary, detail: "" };
  // English backend text sometimes starts with the summary; show it once.
  if (detail.startsWith(action)) detail = detail.slice(action.length).trim();
  if (!detail) return { summary, detail };
  // Backend causes often start lower-case; on their own line they start a sentence. The text is English.
  return { summary, detail: `${detail[0].toLocaleUpperCase("en")}${detail.slice(1)}` };
}

/** Line break between summary and detail in `errorMessage` strings; `ErrorText` splits on it. */
export const DETAIL_SEPARATOR = "\n";

/**
 * `describeError` as one string, for state that holds a string and for plain text (aria, clipboard).
 * Render it with `ErrorText` (InlineError, Field, toasts and StartupProblem do) to show the detail
 * as a smaller secondary line marked as English.
 */
export function errorMessage(reason: unknown, fallback: string): string {
  const { summary, detail } = describeError(reason, fallback);
  return detail ? `${summary}${DETAIL_SEPARATOR}${detail}` : summary;
}

/** Splits an `errorMessage` string back into summary and detail. */
export function splitErrorMessage(message: string): ErrorDescription {
  const at = message.indexOf(DETAIL_SEPARATOR);
  return at < 0 ? { summary: message, detail: "" } : { summary: message.slice(0, at), detail: message.slice(at + 1) };
}

export function formatExpiry(unixSeconds: number): string {
  return formatDateTime(new Date(unixSeconds * 1_000), { dateStyle: "medium", timeStyle: "short" });
}
