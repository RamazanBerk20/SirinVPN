import { t } from "../i18n";
import { House, Database, Devices, GearSix } from "@phosphor-icons/react";

export type Page = "home" | "servers" | "devices" | "settings";
const pages = [
  { id: "home", icon: House },
  { id: "servers", icon: Database },
  { id: "devices", icon: Devices },
  { id: "settings", icon: GearSix },
] as const;

export function Navigation({
  page,
  onChange,
  mobile = false,
}: {
  page: Page;
  onChange: (page: Page) => void;
  mobile?: boolean;
}) {
  return (
    <nav
      className={mobile ? "bottom-navigation" : "primary-navigation"}
      aria-label={mobile ? t("app.nav.mobileLabel") : t("app.nav.label")}
    >
      {pages.map(({ id, icon: Icon }) => (
        <button
          key={id}
          type="button"
          aria-current={page === id ? "page" : undefined}
          onClick={() => onChange(id)}
        >
          <Icon size={25} weight={page === id ? "duotone" : "regular"} />
          <span>
            <strong>{t(`app.nav.${id}`)}</strong>
          </span>
        </button>
      ))}
    </nav>
  );
}
