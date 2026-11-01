import { formatDateTime, getLocale, sourceLocale } from "../i18n";

/**
 * Backend and server errors arrive as English diagnostic text without saying which action failed.
 * English shows the caller's summary of what failed followed by that cause; other languages show
 * the localized summary alone.
 */
export function errorMessage(reason: unknown, fallback: string): string {
  const detail = (typeof reason === "string" ? reason : reason instanceof Error ? reason.message : "").trim();
  if (!detail || getLocale() !== sourceLocale) return fallback;
  const summary = fallback.trim().replace(/\s*Try again\.$/, "");
  return detail.includes(summary) ? detail : `${summary} ${detail}`;
}

export function formatExpiry(unixSeconds: number): string {
  return formatDateTime(new Date(unixSeconds * 1_000), { dateStyle: "medium", timeStyle: "short" });
}
