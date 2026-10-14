import { formatDateTime, getLocale, sourceLocale } from "../i18n";

/**
 * Backend and server errors arrive as English diagnostic text. English shows that specific
 * text; other languages show the caller's localized summary of what failed.
 */
export function errorMessage(reason: unknown, fallback: string): string {
  const detail = typeof reason === "string" ? reason : reason instanceof Error ? reason.message : "";
  if (!detail.trim() || getLocale() !== sourceLocale) return fallback;
  return detail;
}

export function formatExpiry(unixSeconds: number): string {
  return formatDateTime(new Date(unixSeconds * 1_000), { dateStyle: "medium", timeStyle: "short" });
}
