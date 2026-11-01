import { t } from "../i18n";
import { setDemo } from "../platform";

export function DemoBanner() {
  return (
    <aside className="demo-banner" aria-label={t("help.demo.exit")}>
      <span>{t("help.demo.banner")}</span>
      <button type="button" className="secondary-button" onClick={() => setDemo(false)}>{t("help.demo.exit")}</button>
    </aside>
  );
}
