import { t } from "../i18n";
import mark from "../assets/sirin-mark.png";
import { GlobeHemisphereWest, LockKey, Pulse } from "@phosphor-icons/react";

export function Brand({ compact }: { compact: boolean }) {
  return (
    <div className={`brand ${compact ? "compact" : ""}`}>
      <SirinMark />
      <div>
        <strong>{t("common.appName")}</strong>
        <small>{t("app.brand.tagline")}</small>
      </div>
    </div>
  );
}

export function SirinMark({ className = "" }: { className?: string }) {
  return (
    <img
      src={mark}
      className={`brand-mark ${className}`}
      alt=""
      aria-hidden="true"
    />
  );
}

export function PrivacyPromises() {
  return (
    <div className="privacy-promises">
      <span>
        <LockKey size={18} /> {t("app.brand.keysLocal")}
      </span>
      <span>
        <Pulse size={18} /> {t("app.brand.noHistory")}
      </span>
      <span>
        <GlobeHemisphereWest size={18} /> {t("app.brand.noCloud")}
      </span>
    </div>
  );
}
