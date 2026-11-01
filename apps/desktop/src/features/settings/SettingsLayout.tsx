import {
  Key,
  GlobeHemisphereWest,
  GearSix,
  SlidersHorizontal,
  WifiHigh,
  ArrowLeft,
  CaretRight,
} from "@phosphor-icons/react";
import { useId, useRef, type ReactNode } from "react";
import { usePageTransition } from "../../hooks/usePageTransition";
import { pageScrollPort } from "../../lib/scrolling";
import { confirmNavigation } from "../../lib/navigationGuard";
import { t } from "../../i18n";
import { dpadOnly } from "../../platform";

export type SettingsCategory =
  "general" | "connection" | "network" | "recovery" | "maintenance";
const categories = [
  { id: "general", label: "settings.category.general.label", hint: "settings.category.general.hint", icon: GearSix },
  { id: "connection", label: "settings.category.connection.label", hint: "settings.category.connection.hint", icon: WifiHigh },
  { id: "network", label: "settings.category.network.label", hint: "settings.category.network.hint", icon: GlobeHemisphereWest },
  { id: "recovery", label: "settings.category.recovery.label", hint: "settings.category.recovery.hint", icon: Key },
  { id: "maintenance", label: "settings.category.maintenance.label", hint: "settings.category.maintenance.hint", icon: SlidersHorizontal },
] as const;

export function SettingsLayout({
  category,
  onChange,
  children,
  mobile = false,
  detail = false,
  onBack,
}: {
  category: SettingsCategory;
  onChange: (category: SettingsCategory) => void;
  children: ReactNode;
  mobile?: boolean;
  detail?: boolean;
  onBack?: () => void;
}) {
  const id = useId();
  const tabs = useRef<HTMLDivElement>(null);
  const panel = usePageTransition<HTMLDivElement>(category);
  const current = categories.find(item => item.id === category);
  if (mobile) return detail ? <div className="mobile-settings-detail">
    <header className="mobile-page-header"><button className="icon-button" autoFocus={dpadOnly} aria-label={t("common.action.back")} onClick={onBack}><ArrowLeft size={24} /></button><h1>{current && t(current.label)}</h1></header>
    <div className="settings-panel">{children}</div>
  </div> : <div className="mobile-choice-list" aria-label={t("settings.layout.categories")}>
    {categories.map(({ id: value, label, hint, icon: Icon }) => <button key={value} className="mobile-list-row" aria-label={t(label)} aria-describedby={`${id}-${value}-hint`} onClick={() => onChange(value)}>
      <span className="mobile-row-icon"><Icon size={23} /></span><span><strong>{t(label)}</strong><small id={`${id}-${value}-hint`}>{t(hint)}</small></span><CaretRight size={18} />
    </button>)}
  </div>;
  return (
    <div className="settings-layout">
      <div
        className="settings-tabs"
        ref={tabs}
        role="tablist"
        aria-label={t("settings.layout.categories")}
      >
        {categories.map(({ id: value, label, icon: Icon }, index) => (
          <button
            key={value}
            id={`${id}-${value}`}
            type="button"
            role="tab"
            aria-selected={category === value}
            aria-controls={`${id}-panel`}
            tabIndex={category === value ? 0 : -1}
            onClick={() => onChange(value)}
            onKeyDown={(event) => {
              let next = index;
              if (event.key === "ArrowRight" || event.key === "ArrowDown")
                next = (index + 1) % categories.length;
              else if (event.key === "ArrowLeft" || event.key === "ArrowUp")
                next = (index + categories.length - 1) % categories.length;
              else if (event.key === "Home") next = 0;
              else if (event.key === "End") next = categories.length - 1;
              else return;
              event.preventDefault();
              // Clicks are guarded by capture listeners; keyboard selection must ask too.
              if (next === index || !confirmNavigation()) return;
              onChange(categories[next].id);
              document.getElementById(`${id}-${categories[next].id}`)?.focus();
            }}
          >
            <Icon size={20} />
            <span>
              {mobile && value === "maintenance" ? t("settings.category.maintenance.shortLabel") : t(label)}
            </span>
          </button>
        ))}
      </div>
      <div
        className="settings-panel"
        id={`${id}-panel`}
        role="tabpanel"
        tabIndex={0}
        aria-labelledby={`${id}-${category}`}
        ref={panel}
        onFocusCapture={(event) => {
          const target = event.target;
          if (
            !(target instanceof HTMLElement) ||
            target === event.currentTarget ||
            !event.currentTarget.contains(target)
          )
            return;
          requestAnimationFrame(() => {
            if (!target.isConnected || !tabs.current) return;
            const top = target.getBoundingClientRect().top;
            const visibleTop = tabs.current.getBoundingClientRect().bottom + 12;
            if (top < visibleTop)
              pageScrollPort().scrollBy({
                top: top - visibleTop,
                behavior: "auto",
              });
          });
        }}
      >
        {children}
      </div>
    </div>
  );
}
