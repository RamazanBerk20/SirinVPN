import { useEffect, useRef, useState } from "react";
import { api } from "../../api";
import { invoke, isAndroid } from "../../platform";
import { InlineError } from "../../components/ui";
import type { ServerProfile, WifiPolicySnapshot } from "../../types";

const networkLabels = {
  unavailable: "No active network detected",
  other_network: "The active connection is not Wi-Fi",
  trusted_wifi: "Current network: marked trusted",
  untrusted_wifi: "Current network: not marked trusted",
};
const statusLabels = {
  disabled: "Automatic connection is off.",
  waiting_for_wifi: "Waiting for a Wi-Fi network that is not marked trusted.",
  trusted: "This network is marked trusted. Existing VPN sessions stay connected.",
  connecting: "Connecting with the automation server’s saved settings…",
  session_active: "A VPN session or its protection is already active.",
  waiting_for_network_change: "Automation paused on this network. It resumes when the network changes; you can also connect manually.",
  needs_attention: "Automatic connection could not finish. Open Home to check the connection and try manually.",
  needs_authorization: "Connect once from Home to authorize VPN controls for this account.",
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
        if (!initialized) {
          applySnapshot(next, profiles);
          setReviewedToken(next.current_network_token);
          initialized = true;
        } else {
          setSnapshot(next);
          if (next.policy.server_id) setSelected(next.policy.server_id);
        }
      } catch (reason) {
        if (current()) setError(initialized
          ? "The current network status could not be refreshed. Refresh network to try again."
          : String(reason));
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
    setBusy(true); setError("");
    try {
      await operation();
      const [next, profiles] = await Promise.all([api.getWifiPolicy(), api.listServers()]);
      if (!active.current || epoch !== generation.current) return;
      applySnapshot(next, profiles);
      if (reviewNetwork) { setReviewedToken(next.current_network_token); setLabel(""); }
    } catch (e) {
      if (active.current && epoch === generation.current) {
        setError(String(e));
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
    ? "Allow precise location so Android can identify this Wi-Fi. SirinVPN does not collect your location."
    : locationOff ? "Turn on Location in Android so this Wi-Fi can be identified."
    : !snapshot?.can_trust_current || !snapshot.current_network_token
    ? "The operating system cannot reliably identify this saved Wi-Fi connection. It cannot be marked trusted."
    : networkChanged ? "The network changed. Select Refresh network to review it before marking it trusted." : "";
  return <section className="settings-card wifi-settings" aria-label="Wi-Fi trust" aria-busy={busy}>
    <div className="settings-section-heading"><h2>Wi-Fi trust</h2></div>
    <label className="preference-row">
      <span><strong>Connect on Wi-Fi not marked trusted</strong><small>Automatic connection applies on Wi-Fi networks that are not marked trusted. Uses the server chosen below and its saved connection settings.</small></span>
      <input type="checkbox" role="switch" aria-label="Connect on Wi-Fi not marked trusted"
        checked={snapshot?.policy.enabled ?? false} disabled={busy || !snapshot || !selected}
        onChange={(e) => { const enabled = e.target.checked; void action(() => api.setWifiPolicy({ enabled, server_id: selected })); }} />
    </label>
    <label className="field"><span>Automatic connection server</span>
      <select aria-label="Automatic connection server" value={selected} disabled={busy || !snapshot || !servers.length}
        onChange={(e) => { const id = e.target.value; setSelected(id); void action(() => api.setWifiPolicy({ enabled: snapshot?.policy.enabled ?? false, server_id: id })); }}>
        {!servers.length && <option value="">Add a server first</option>}
        {servers.map((server) => <option key={server.id} value={server.id}>{server.name}</option>)}
      </select>
    </label>
    {snapshot && <>
      <p className="settings-note">{networkLabels[snapshot.current_network]}{currentName && <> — <strong>{currentName}</strong></>}</p>
      {snapshot.policy.enabled && <p className={snapshot.automation_status === "waiting_for_network_change" ? "wifi-paused" : "settings-note"} role="status">{statusLabels[snapshot.automation_status]}</p>}
      {snapshot.current_network === "untrusted_wifi" && <>
        {permissionRequired || locationOff ? <div className="wifi-access">
          <p id="wifi-trust-reason" className="settings-note">{trustReason}</p>
          <div className="settings-action-row">
            {permissionRequired && <button className="secondary-button" disabled={busy} onClick={() => void action(async () => {
              if (!await invoke<boolean>("android_wifi_permission"))
                throw new Error("Wi-Fi access was not granted. Open App permissions, choose Location and enable Precise location.");
            }, true)}>Allow Wi-Fi access</button>}
            {locationOff && <button className="secondary-button" disabled={busy} onClick={() => void invoke("android_location_settings")}>Open Location settings</button>}
            <button className="text-button" onClick={() => void invoke("android_background_wifi_settings")}>App permissions</button>
          </div>
        </div> : <>
        <div className="settings-action-row">
          <label className="field"><span>Network name (optional)</span><input value={label} maxLength={80} placeholder="For example, Home" onChange={(e) => setLabel(e.target.value)} disabled={busy || Boolean(trustReason)} /></label>
          <button className="secondary-button" disabled={busy || Boolean(trustReason)}
            aria-describedby={trustReason ? "wifi-trust-reason" : undefined}
            onClick={() => void action(() => api.trustCurrentWifi(reviewedToken!, label.trim() || "Wi-Fi exception"), true)}>Trust current Wi-Fi</button>
        </div>
        {trustReason && <p id="wifi-trust-reason" className="settings-note">{trustReason}</p>}
        </>}
      </>}
      {snapshot.trusted_networks.length > 0 && <ul className="plain-list">{snapshot.trusted_networks.map((network) => {
        const osName = snapshot.network_names?.[network.id];
        const friendly = network.label !== "Wi-Fi exception" ? network.label : "";
        const name = osName || friendly || `Saved Wi-Fi (${network.id.slice(0, 8)})`;
        return <li key={network.id} className="settings-action-row">
          <div><strong>{name}</strong>
            {osName && friendly && friendly !== osName && <p className="settings-note">Label: {friendly}</p>}
            <p className="settings-note">{network.id === snapshot.current_network_token ? "Current network" : "Saved Wi-Fi connection"}{!osName && " · OS name unavailable"}</p>
          </div>
          <button className="text-button" aria-label={`Remove trust for ${name}`} disabled={busy} onClick={() => void action(() => api.forgetTrustedWifi(network.id))}>Remove trust</button>
        </li>;
      })}</ul>}
    </>}
    <button className="text-button" disabled={busy} onClick={() => void action(async () => {}, true)}>Refresh network</button>
    {isAndroid && snapshot?.can_trust_current && <div>
      <p className="settings-note">For trusted Wi-Fi exceptions while the app is closed, allow Location → Allow all the time in Android. A hidden identity is treated as untrusted.</p>
      <button className="text-button" onClick={() => void invoke("android_background_wifi_settings")}>Background Wi-Fi permissions</button>
    </div>}
    <p className="settings-note">Trust is your exception to automatic connection, not a network security assessment. It applies to a saved Wi-Fi connection and stores no history of networks visited.</p>
    <p className="settings-note">OS Wi-Fi names are read only for display on this device. They are not stored by SirinVPN or sent to the VPS.</p>
    <p className="settings-note">{isAndroid ? "An Android notification keeps enabled automation visible while the app is closed. Disconnect pauses it on the current network; Android’s Stop app control ends monitoring." : "Monitoring continues while SirinVPN is hidden in the tray. Quit app stops monitoring, even if an existing VPN tunnel stays connected."}</p>
    <InlineError message={error} />
  </section>;
}
