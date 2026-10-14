import { useEffect, useRef, useState } from "react";
import { api } from "../../api";
import { invoke, isAndroid } from "../../platform";
import { InlineError } from "../../components/ui";
import { errorMessage } from "../../lib/errors";
import type { ServerProfile, WifiPolicySnapshot } from "../../types";
import { t, type MessageKey } from "../../i18n";
import { Rich } from "../../i18n/Rich";
import { useInfoHint } from "../../components/InfoHint";

/** Stored label for a trusted network the user did not name; never displayed. */
const UNNAMED_NETWORK_LABEL = "Wi-Fi exception";
const networkLabels: Record<WifiPolicySnapshot["current_network"], MessageKey> = {
  unavailable: "settings.wifi.network.unavailable",
  other_network: "settings.wifi.network.otherNetwork",
  trusted_wifi: "settings.wifi.network.trusted",
  untrusted_wifi: "settings.wifi.network.untrusted",
};
const statusLabels: Record<WifiPolicySnapshot["automation_status"], MessageKey> = {
  disabled: "settings.wifi.status.disabled",
  waiting_for_wifi: "settings.wifi.status.waitingForWifi",
  trusted: "settings.wifi.status.trusted",
  connecting: "settings.wifi.status.connecting",
  session_active: "settings.wifi.status.sessionActive",
  waiting_for_network_change: "settings.wifi.status.paused",
  needs_attention: "settings.wifi.status.needsAttention",
  needs_authorization: "settings.wifi.status.needsAuthorization",
};

export function WifiSettings() {
  const [snapshot, setSnapshot] = useState<WifiPolicySnapshot | null>(null);
  const [servers, setServers] = useState<ServerProfile[]>([]);
  const [selected, setSelected] = useState("");
  const [label, setLabel] = useState("");
  const [reviewedToken, setReviewedToken] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const generation = useRef(0);
  const active = useRef(false);
  const writing = useRef(false);
  // A later successful poll clears only errors that polling itself reported.
  const pollFailed = useRef(false);
  const [info, infoPanel] = useInfoHint(
    t(isAndroid ? "settings.wifi.infoAndroid" : "settings.wifi.infoDesktop"),
    t("settings.wifi.infoLabel"),
  );
  const applySnapshot = (next: WifiPolicySnapshot, profiles?: ServerProfile[]) => {
    setSnapshot(next);
    if (profiles) setServers(profiles);
    setSelected(next.policy.server_id ?? profiles?.[0]?.id ?? servers[0]?.id ?? "");
  };
  useEffect(() => {
    active.current = true;
    ++generation.current;
    let mounted = true;
    let polling = false;
    let initialized = false;
    let visibility = 0;
    let refreshAfterPending = false;
    let timer: ReturnType<typeof setInterval> | undefined;
    const refresh = async () => {
      if (!mounted || document.hidden || writing.current) return;
      if (polling) { refreshAfterPending = true; return; }
      polling = true;
      const request = generation.current;
      const visibleRequest = visibility;
      const current = () => mounted && request === generation.current &&
        visibleRequest === visibility && !document.hidden;
      try {
        const [next, profiles] = await Promise.all([
          api.getWifiPolicy(),
          initialized ? Promise.resolve(undefined) : api.listServers(),
        ]);
        if (!current()) return;
        if (pollFailed.current) { pollFailed.current = false; setError(""); }
        if (!initialized) {
          applySnapshot(next, profiles);
          setReviewedToken(next.current_network_token);
          initialized = true;
        } else {
          setSnapshot(next);
          if (next.policy.server_id) setSelected(next.policy.server_id);
        }
      } catch (reason) {
        if (current()) {
          pollFailed.current = true;
          setError(initialized
            ? t("settings.wifi.refreshFailed")
            : errorMessage(reason, t("settings.wifi.loadFailed")));
        }
      } finally {
        polling = false;
        if (refreshAfterPending) {
          refreshAfterPending = false;
          void refresh();
        }
      }
    };
    const resume = () => {
      ++visibility;
      clearInterval(timer);
      if (document.hidden) return;
      void refresh();
      timer = setInterval(() => void refresh(), 5000);
    };
    resume();
    document.addEventListener("visibilitychange", resume);
    return () => {
      mounted = false;
      active.current = false;
      ++generation.current;
      clearInterval(timer);
      document.removeEventListener("visibilitychange", resume);
    };
  }, []);
  async function action(operation: () => Promise<unknown>, reviewNetwork = false) {
    if (writing.current) return;
    const epoch = ++generation.current;
    writing.current = true;
    setBusy(true); setError(""); pollFailed.current = false;
    try {
      await operation();
      const [next, profiles] = await Promise.all([api.getWifiPolicy(), api.listServers()]);
      if (!active.current || epoch !== generation.current) return;
      applySnapshot(next, profiles);
      if (reviewNetwork) { setReviewedToken(next.current_network_token); setLabel(""); }
    } catch (e) {
      if (active.current && epoch === generation.current) {
        setError(errorMessage(e, t("settings.wifi.saveFailed")));
        setSelected(snapshot?.policy.server_id ?? servers[0]?.id ?? "");
      }
    } finally {
      writing.current = false;
      if (active.current && epoch === generation.current) setBusy(false);
    }
  }
  const networkChanged = snapshot?.current_network_token !== reviewedToken;
  const currentName = snapshot?.network_names?.[snapshot.current_network_token ?? ""];
  const permissionRequired = isAndroid && snapshot?.permission_required === true;
  const locationOff = isAndroid && snapshot?.location_enabled === false;
  const trustReason = permissionRequired
    ? t("settings.wifi.access.permission")
    : locationOff ? t("settings.wifi.access.locationOff")
    : !snapshot?.can_trust_current || !snapshot.current_network_token
    ? t("settings.wifi.access.unidentified")
    : networkChanged ? t("settings.wifi.access.changed") : "";
  return <section className="settings-card wifi-settings" aria-label={t("settings.wifi.title")} aria-busy={busy}>
    <div className="settings-section-heading"><h2>{t("settings.wifi.title")}</h2>{info}</div>
    {infoPanel}
    <label className="preference-row">
      <span><strong>{t("settings.wifi.toggle.label")}</strong><small>{t("settings.wifi.toggle.summary")}</small></span>
      <input type="checkbox" role="switch" aria-label={t("settings.wifi.toggle.label")}
        checked={snapshot?.policy.enabled ?? false} disabled={busy || !snapshot || !selected}
        onChange={(e) => { const enabled = e.target.checked; void action(() => api.setWifiPolicy({ enabled, server_id: selected })); }} />
    </label>
    <label className="field"><span>{t("settings.wifi.server.label")}</span>
      <select aria-label={t("settings.wifi.server.label")} value={selected} disabled={busy || !snapshot || !servers.length}
        onChange={(e) => { const id = e.target.value; setSelected(id); void action(() => api.setWifiPolicy({ enabled: snapshot?.policy.enabled ?? false, server_id: id })); }}>
        {!servers.length && <option value="">{t("settings.wifi.server.empty")}</option>}
        {servers.map((server) => <option key={server.id} value={server.id}>{server.name}</option>)}
      </select>
    </label>
    {snapshot && <>
      <p className="settings-note">{currentName
        ? <Rich id="settings.wifi.network.named" params={{ status: t(networkLabels[snapshot.current_network]), name: currentName }} tags={{ strong: content => <strong>{content}</strong> }} />
        : t(networkLabels[snapshot.current_network])}</p>
      {snapshot.policy.enabled && <p className={snapshot.automation_status === "waiting_for_network_change" ? "wifi-paused" : "settings-note"} role="status">{t(statusLabels[snapshot.automation_status])}</p>}
      {snapshot.current_network === "untrusted_wifi" && <>
        {permissionRequired || locationOff ? <div className="wifi-access">
          <p id="wifi-trust-reason" className="settings-note">{trustReason}</p>
          <div className="settings-action-row">
            {permissionRequired && <button className="secondary-button" disabled={busy} onClick={() => void action(async () => {
              if (!await invoke<boolean>("android_wifi_permission"))
                throw new Error(t("settings.wifi.access.denied"));
            }, true)}>{t("settings.wifi.access.allow")}</button>}
            {locationOff && <button className="secondary-button" disabled={busy} onClick={() => void invoke("android_location_settings")}>{t("settings.wifi.access.locationSettings")}</button>}
            <button className="text-button" onClick={() => void invoke("android_background_wifi_settings")}>{t("settings.wifi.access.appPermissions")}</button>
          </div>
        </div> : <>
        <div className="settings-action-row">
          <label className="field"><span>{t("settings.wifi.trust.label")}</span><input value={label} maxLength={80} placeholder={t("settings.wifi.trust.placeholder")} onChange={(e) => setLabel(e.target.value)} disabled={busy || Boolean(trustReason)} /></label>
          <button className="secondary-button" disabled={busy || Boolean(trustReason)}
            aria-describedby={trustReason ? "wifi-trust-reason" : undefined}
            onClick={() => void action(() => api.trustCurrentWifi(reviewedToken!, label.trim() || UNNAMED_NETWORK_LABEL), true)}>{t("settings.wifi.trust.action")}</button>
        </div>
        {trustReason && <p id="wifi-trust-reason" className="settings-note">{trustReason}</p>}
        </>}
      </>}
      {snapshot.trusted_networks.length > 0 && <ul className="plain-list">{snapshot.trusted_networks.map((network) => {
        const osName = snapshot.network_names?.[network.id];
        const friendly = network.label !== UNNAMED_NETWORK_LABEL ? network.label : "";
        const name = osName || friendly || t("settings.wifi.trusted.savedName", { id: network.id.slice(0, 8) });
        const kind = t(network.id === snapshot.current_network_token ? "settings.wifi.trusted.current" : "settings.wifi.trusted.saved");
        return <li key={network.id} className="settings-action-row trusted-wifi-row">
          <div><strong>{name}</strong>
            {osName && friendly && friendly !== osName && <p className="settings-note">{t("settings.wifi.trusted.label", { label: friendly })}</p>}
            <p className="settings-note">{osName ? kind : t("common.separator.pair", { first: kind, second: t("settings.wifi.trusted.nameUnavailable") })}</p>
          </div>
          <button className={isAndroid ? "secondary-button" : "text-button"} aria-label={t("settings.wifi.trusted.removeLabel", { name })} disabled={busy} onClick={() => void action(() => api.forgetTrustedWifi(network.id))}>{t("settings.wifi.trusted.remove")}</button>
        </li>;
      })}</ul>}
    </>}
    <button className="text-button" disabled={busy} onClick={() => void action(async () => {}, true)}>{t("settings.wifi.refresh")}</button>
    {isAndroid && snapshot?.can_trust_current && <div>
      <p className="settings-note">{t("settings.wifi.background.summary")}</p>
      <button className="text-button" onClick={() => void invoke("android_background_wifi_settings")}>{t("settings.wifi.background.action")}</button>
    </div>}
    <InlineError message={error} />
  </section>;
}
