import { invoke, isAndroid } from "../../platform";
import type { ThemePreference } from "./preferences";

export type Theme = "light" | "dark";

export function resolveTheme(preference: ThemePreference | undefined, systemLight: boolean): Theme {
  return preference === "light" || preference === "dark" ? preference : systemLight ? "light" : "dark";
}

/** Applies the theme to the document and keeps following the system while the preference is "system". */
export function followTheme(preference: ThemePreference | undefined): () => void {
  const system = window.matchMedia?.("(prefers-color-scheme: light)");
  const apply = () => {
    const theme = resolveTheme(preference, system?.matches ?? false);
    document.documentElement.dataset.theme = theme;
    // Android draws the status and navigation bars outside the WebView.
    if (isAndroid) invoke("android_system_bars", { light: theme === "light" }).catch(() => {});
  };
  apply();
  system?.addEventListener("change", apply);
  return () => system?.removeEventListener("change", apply);
}
