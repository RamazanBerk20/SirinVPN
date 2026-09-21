import mark from "../assets/sirin-mark.png";
import { GlobeHemisphereWest, LockKey, Pulse } from "@phosphor-icons/react";

export function Brand({ compact }: { compact: boolean }) {
  return (
    <div className={`brand ${compact ? "compact" : ""}`}>
      <SirinMark />
      <div>
        <strong>SirinVPN</strong>
        <small>Ultra-private. Self-hosted.</small>
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
        <LockKey size={18} /> Client keys stay local
      </span>
      <span>
        <Pulse size={18} /> No activity history
      </span>
      <span>
        <GlobeHemisphereWest size={18} /> No SirinVPN cloud
      </span>
    </div>
  );
}
