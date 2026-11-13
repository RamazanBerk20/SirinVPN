import { api } from "../api";
import { loadLocale, preferredLocale, setLocale, SYSTEM_LANGUAGE } from ".";
import { pushNativeText } from "./native";

let applied: string | null = null;
let generation = 0;

/** Development builds accept `?lang=<tag>` (e.g. the pseudo-locales en-XA, ar-XB) for layout checks. */
function devOverride(): string | null {
  if (!import.meta.env.DEV || typeof location === "undefined") return null;
  return new URLSearchParams(location.search).get("lang");
}

/**
 * Applies a saved language preference ("system" or a tag): loads the catalog, switches the
 * interface (components re-render through useLocale) and sends the native text to the shell.
 */
export async function applyLanguage(preference: string | null | undefined): Promise<void> {
  const choice = devOverride() ?? preference ?? SYSTEM_LANGUAGE;
  if (choice === applied) return;
  applied = choice;
  const request = ++generation;
  const tag = preferredLocale(choice);
  await loadLocale(tag);
  if (request !== generation) return;
  setLocale(tag);
  await pushNativeText();
}

/** Before the first render: the saved language, so no English flashes first. Gives up after 1.5 s. */
export async function initLanguage(): Promise<void> {
  const saved = api.getAppPreferences().then(snapshot => snapshot.preferences.language, () => undefined);
  const timeout = new Promise<undefined>(resolve => setTimeout(resolve, 1_500));
  await applyLanguage(await Promise.race([saved, timeout]));
}
