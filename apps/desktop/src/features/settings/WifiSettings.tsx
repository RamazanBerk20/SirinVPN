import { useEffect, useRef, useState } from "react";
import { ArrowClockwise } from "@phosphor-icons/react";
import { api } from "../../api";
import { invoke, isAndroid } from "../../platform";
import { SettingsNotice } from "./SettingsParts";
import { InlineError } from "../../components/ui";
import { notify } from "../../components/Toasts";
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
/** Android withholds the Wi-Fi name: each case's explanation and the one action that fixes it. */
const accessNotes = {
  locationOff: { text: "settings.wifi.access.locationOff", action: "settings.wifi.access.locationSettings", command: "android_location_settings" },
  permission: { text: "settings.wifi.access.permission", action: "settings.wifi.access.allow", command: "android_wifi_permission" },
  background: { text: "settings.wifi.access.background", action: "settings.wifi.access.allowAlways", command: "android_wifi_permission" },
} satisfies Record<string, { text: MessageKey; action: MessageKey; command: string }>;

export function WifiSettings() {
  const [snapshot, setSnapshot] = useState<WifiPolicySnapshot | null>(null);
  const [servers, setServers] = useState<ServerProfile[]>([]);
  const [selected, setSelected] = useState("");
  const [label, setLabel] = useState("");
  // Set when polling saw the network change, so the user re-reads the name before trusting it.
  const [networkChanged, setNetworkChanged] = useState(false);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState("");
  const [loaded, setLoaded] = useState(false);
  const generation = useRef(0);
  const active = useRef(false);
  const writing = useRef(false);
  const poll = useRef<() => void>(() => {});
  // The network token the user was last shown; a different one means the network changed under them.
  const seenToken = useRef<string | null>(null);
  // A later successful poll clears only errors that polling itself reported.
  const pollFailed = useRef(false);
  const [info, infoPanel] = useInfoHint(t(isAndroid ? "settings.wifi.infoAndroid" : "settings.wifi.infoDesktop"), t("settings.wifi.infoLabel"));
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
          seenToken.current = next.current_network_token;
          initialized = true;
          setLoaded(true);
        } else {
          setSnapshot(next);
          if (next.policy.server_id) setSelected(next.policy.server_id);
          // Follow a network change at once; the backend still refuses to trust a network other than the one shown.
          if (seenToken.current !== next.current_network_token) {
            seenToken.current = next.current_network_token;
            setNetworkChanged(true); setLabel("");
          }
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
    poll.current = () => void refresh();
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
  async function action(key: string, operation: () => Promise<unknown>, done?: (next: WifiPolicySnapshot) => void) {
    const failure = t(key === "refresh" ? "settings.wifi.refreshFailed" : "settings.wifi.saveFailed");
    if (writing.current) return;
    const epoch = ++generation.current;
    writing.current = true;
    setBusy(key); setError(""); pollFailed.current = false;
    try {
      await operation();
      const [next, profiles] = await Promise.all([api.getWifiPolicy(), api.listServers()]);
      if (!active.current || epoch !== generation.current) return;
      applySnapshot(next, profiles);
      seenToken.current = next.current_network_token; setNetworkChanged(false);
      done?.(next);
    } catch (e) {
      if (active.current && epoch === generation.current) {
        setError(errorMessage(e, failure));
        setSelected(snapshot?.policy.server_id ?? servers[0]?.id ?? "");
      }
    } finally {
      writing.current = false;
      if (active.current && epoch === generation.current) setBusy(null);
    }
  }
  const enabled = snapshot?.policy.enabled ?? false;
  const currentName = snapshot?.network_names?.[snapshot.current_network_token ?? ""];
  const trustBlocked = !snapshot?.can_trust_current || !snapshot.current_network_token;
  // Hidden names get a stable number from their place in the list, never a fragment of the token.
  const trusted = (snapshot?.trusted_networks ?? []).map((network, index) => {
    const osName = snapshot?.network_names?.[network.id];
    const friendly = network.label !== UNNAMED_NETWORK_LABEL ? network.label : "";
    return { network, osName, friendly, name: osName || friendly || t("settings.wifi.trusted.unnamed", { number: index + 1 }) };
  });
  const access = snapshot?.android_access;
  const onWifi = snapshot?.current_network === "trusted_wifi" || snapshot?.current_network === "untrusted_wifi";
  // Without the name every Wi-Fi counts as untrusted, so auto-connect fails safe; say what is missing where it matters.
  const missing = !access ? null : !access.location_enabled ? "locationOff" : access.location === "denied" ? "permission"
    : access.location === "while_in_use" ? "background" : null;
  const note = missing && (enabled || onWifi || trusted.length > 0) ? accessNotes[missing] : null;
  return <section className="settings-card wifi-settings" aria-label={t("settings.wifi.title")} aria-busy={Boolean(busy)}>
    <div className="settings-section-heading"><h2>{t("settings.wifi.title")}</h2>{info}</div>
    {infoPanel}
    {!loaded && error ? <InlineError message={error} onRetry={() => poll.current()} /> : <>
      <label className="preference-row">
        <span><strong>{t("settings.wifi.toggle.label")}</strong><small>{t("settings.wifi.toggle.summary")}</small></span>
        <input type="checkbox" role="switch" aria-label={t("settings.wifi.toggle.label")}
          checked={enabled} disabled={Boolean(busy) || !snapshot || !selected}
          onChange={(e) => { const next = e.target.checked; void action("toggle", () => api.setWifiPolicy({ enabled: next, server_id: selected })); }} />
      </label>
      {/* Just after turning it on, the native status can still read "disabled": say it is starting instead of "off". */}
      {snapshot && enabled && <p className={snapshot.automation_status === "waiting_for_network_change" ? "wifi-paused" : "settings-note"} role="status">{t(snapshot.automation_status === "disabled" ? "settings.wifi.status.starting" : statusLabels[snapshot.automation_status])}</p>}
      {enabled && access?.background_restricted && <SettingsNotice tone="warning"
        action={{ label: t("settings.wifi.access.appSettings"), onClick: () => void invoke("android_app_settings") }}>{t("settings.wifi.access.restricted")}</SettingsNotice>}
      <label className="field"><span>{t("settings.wifi.server.label")}</span>
        <select aria-label={t("settings.wifi.server.label")} value={selected} disabled={Boolean(busy) || !snapshot || !servers.length || !enabled}
          onChange={(e) => { const id = e.target.value; setSelected(id); void action("server", () => api.setWifiPolicy({ enabled, server_id: id })); }}>
          {!servers.length && <option value="">{t("settings.wifi.server.empty")}</option>}
          {servers.map((server) => <option key={server.id} value={server.id}>{server.name}</option>)}
        </select>
        {!enabled && servers.length > 0 && <small>{t("settings.wifi.server.offHint")}</small>}
      </label>
      {snapshot && <div className="wifi-network">
        <h3>{t("settings.wifi.network.heading")}</h3>
        <div className="wifi-network-line">
          <p>{currentName
            ? <Rich id="settings.wifi.network.named" params={{ status: t(networkLabels[snapshot.current_network]), name: currentName }} tags={{ strong: content => <strong>{content}</strong> }} />
            : t(networkLabels[snapshot.current_network])}</p>
          <button type="button" className="icon-button" aria-label={t("settings.wifi.refresh")} title={t("settings.wifi.refresh")} disabled={Boolean(busy)}
            onClick={() => void action("refresh", async () => {})}><ArrowClockwise size={18} className={busy === "refresh" ? "spin" : undefined} /></button>
        </div>
        {networkChanged && snapshot.current_network === "untrusted_wifi" && <p className="settings-note" role="status">{t(currentName ? "settings.wifi.access.changed" : "settings.wifi.access.changedUnnamed")}</p>}
        {note && <SettingsNotice tone="warning" action={{ label: t(note.action), disabled: Boolean(busy),
          onClick: () => void action("access", () => invoke(note.command)) }}>{t(note.text)}</SettingsNotice>}
        {snapshot.current_network === "untrusted_wifi" && (trustBlocked
          ? !note && <p className="settings-note">{t("settings.wifi.access.unidentified")}</p>
          : <div className="wifi-trust-form">
            <label className="field"><span>{t("settings.wifi.trust.label")}</span><input value={label} maxLength={80} placeholder={t("settings.wifi.trust.placeholder")} onChange={(e) => setLabel(e.target.value)} disabled={Boolean(busy)} /></label>
            <button className="secondary-button" disabled={Boolean(busy)}
              onClick={() => { const name = label.trim() || currentName || t("settings.wifi.trusted.unnamed", { number: trusted.length + 1 });
                void action("trust", () => api.trustCurrentWifi(snapshot.current_network_token!, label.trim() || UNNAMED_NETWORK_LABEL), () => { setLabel(""); notify(t("settings.wifi.trust.trusted", { name })); }); }}>
              {t("settings.wifi.trust.action")}</button>
          </div>)}
      </div>}
      {trusted.length > 0 && <div className="wifi-trusted">
        <h3>{t("settings.wifi.trusted.title")}</h3>
        <ul className="plain-list">{trusted.map(({ network, osName, friendly, name }) => <li key={network.id} className="trusted-wifi-row">
          <div><strong>{name}</strong>
            <small>{[
              network.id === snapshot?.current_network_token ? t("settings.wifi.trusted.current") : null,
              osName && friendly && friendly !== osName ? t("settings.wifi.trusted.label", { label: friendly }) : null,
            ].filter(Boolean).join(" · ") || t("settings.wifi.trusted.saved")}</small>
          </div>
          <button className="text-button" aria-label={t("settings.wifi.trusted.removeLabel", { name })} disabled={Boolean(busy)}
            onClick={() => void action(network.id, () => api.forgetTrustedWifi(network.id), () => notify(t("settings.wifi.trusted.removed", { name })))}>
            {busy === network.id ? t("settings.wifi.trusted.removing") : t("settings.wifi.trusted.remove")}</button>
        </li>)}</ul>
        {trusted.some((item) => !item.osName) && <p className="settings-note">{t(isAndroid ? "settings.wifi.trusted.namesHiddenAndroid" : "settings.wifi.trusted.namesHidden")}</p>}
      </div>}
      <InlineError message={error} onRetry={loaded ? () => void action("refresh", async () => {}) : undefined} retryDisabled={Boolean(busy)} />
    </>}
  </section>;
}
