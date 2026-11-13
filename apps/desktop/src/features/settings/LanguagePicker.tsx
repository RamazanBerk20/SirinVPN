import { Translate } from "@phosphor-icons/react";
import { LANGUAGES, pseudoLocales, resolveLocale, SYSTEM_LANGUAGE, t } from "../../i18n";
import { usePreferences } from "./PreferencesProvider";

/** The saved choice as one of the offered values (Android may report a regional tag). */
function selected(language: string | undefined): string {
  if (!language || language === SYSTEM_LANGUAGE) return SYSTEM_LANGUAGE;
  if (import.meta.env.DEV && Object.values(pseudoLocales).includes(language as never)) return language;
  return resolveLocale([language]);
}

/**
 * Language choice: "System default" and each language named in itself. `compact` is the small
 * control on the first onboarding screen, so nobody is stuck in a language they cannot read.
 */
export function LanguagePicker({ compact = false, id }: { compact?: boolean; id?: string }) {
  const { snapshot, loading, saving, change } = usePreferences();
  const select = (
    <select
      id={id}
      className="language-select"
      // The label names the control in the current language; the icon says "language" to everyone.
      aria-label={compact ? t("settings.general.language.label") : undefined}
      value={selected(snapshot?.preferences.language)}
      disabled={!snapshot || loading || saving}
      onChange={event => void change("language", event.target.value)}
    >
      <option value={SYSTEM_LANGUAGE}>{t("settings.general.language.system")}</option>
      {LANGUAGES.map(language => <option key={language.tag} value={language.tag} lang={language.tag} dir="auto">{language.name}</option>)}
      {import.meta.env.DEV && <>
        <option value={pseudoLocales.expanded}>{t("settings.general.language.devExpanded")}</option>
        <option value={pseudoLocales.rtl}>{t("settings.general.language.devRtl")}</option>
      </>}
    </select>
  );
  if (!compact) return select;
  return <label className="language-picker"><Translate size={18} aria-hidden="true" />{select}</label>;
}
