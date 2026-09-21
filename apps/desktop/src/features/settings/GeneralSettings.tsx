import { WifiSettings } from "./WifiSettings";
import { invoke } from "../../platform";
import { useEffect, useState } from "react";
import { api } from "../../api";
import type { ServerProfile } from "../../types";
import { ArrowClockwise, Bell, Desktop } from "@phosphor-icons/react";
import { InlineError } from "../../components/ui";
import type { ClientPlatform } from "../../types";
import type { AppPreferences } from "./preferences";
import { usePreferences } from "./PreferencesProvider";

export function GeneralSettings({
  platform,
  onCheckUpdates,
  onReviewComponentUpdate,
}: {
  platform: ClientPlatform;
  onCheckUpdates?: () => void;
  onReviewComponentUpdate?: () => void;
}) {
  const [tileMessage, setTileMessage] = useState("");
  const {
    snapshot,
    changedKey,
    loading,
    saving,
    error,
    status,
    refresh,
    change,
    testNotification,
  } = usePreferences();
  const row = (
    key: keyof AppPreferences,
    label: string,
    description: string,
    unavailable = false,
  ) => (
    <label className="preference-row">
      <span>
        <strong>{label}</strong>
        <small>{description}</small>
        {changedKey === key && (
          <small
            className={error ? "danger-text" : "preference-feedback"}
            role={error ? "alert" : "status"}
          >
            {saving ? "Saving…" : error || status}
          </small>
        )}
      </span>
      <input
        type="checkbox"
        role="switch"
        aria-label={label}
        checked={(snapshot?.preferences[key] ?? false) && (key !== "notifications" || platform !== "android" || snapshot?.notification_permission === "granted")}
        disabled={loading || saving || !snapshot || unavailable}
        onChange={(event) => void change(key, event.target.checked)}
      />
    </label>
  );
  return (
    <div className="settings-sections" aria-busy={loading || saving}>
      {error && !changedKey && (
        <div className="preferences-error">
          <InlineError message={error} />
          {!snapshot && (
            <button
              className="secondary-button"
              disabled={loading}
              onClick={() => void refresh()}
            >
              Retry
            </button>
          )}
        </div>
      )}
      {platform === "desktop" && (
        <section className="settings-card">
          <div className="settings-section-heading">
            <Desktop size={21} />
            <h2>Startup & window</h2>
          </div>
          {row(
            "start_on_login",
            "Start on system startup",
            snapshot && !snapshot.startup_available
              ? "Startup registration is unavailable on this system."
              : "Open SirinVPN when you sign in to your computer.",
            !snapshot?.startup_available,
          )}
          {row(
            "launch_minimized",
            "Launch minimized",
            "Start in the taskbar, or in the tray when Close to tray is enabled.",
          )}
          {row(
            "close_to_tray",
            "Close to tray",
            snapshot && !snapshot.tray_available
              ? "A system tray is unavailable in this desktop session."
              : "Keep the app running when you close its window. Reopen it from the tray.",
            !snapshot?.tray_available,
          )}
          <p className="settings-note">
            These options control the app window. Connect from Home; closing or
            quitting the app leaves the VPN running.
          </p>
        </section>
      )}
      <WifiSettings />
      {platform === "android" && <section className="settings-card">
        <h2>Android VPN controls</h2>
        <QuickProfile />
        <p>The VPN continues when you close SirinVPN. Android controls Always-on VPN and Block connections without VPN.</p>
        <div className="settings-action-row"><button className="secondary-button" onClick={() => void invoke("android_vpn_settings")}>VPN & kill switch settings</button>
        <button className="secondary-button" onClick={() => void invoke<unknown>("android_add_tile")
          .then(value => setTileMessage(typeof value === "string" ? value : ""))
          .catch(() => setTileMessage("Open Quick Settings, tap Edit and add SirinVPN."))}>Add Quick Settings tile</button></div>
        {tileMessage && <p role="status">{tileMessage}</p>}
      </section>}
      <section className="settings-card">
        <div className="settings-section-heading">
          <Bell size={21} />
          <h2>Notifications & interface</h2>
        </div>
        {(platform === "desktop" || platform === "android") && <>
          {row(
            "notifications",
            "Connection notifications",
            platform === "android" ? "Show connection changes and interruptions while the app is closed. The active VPN notification is controlled by Android." : "Show connection changes and interruptions, including while the app is in the tray.",
          )}
          <div className="settings-action-row">
            <p>Alerts never include server names, addresses, or keys.</p>
            <div className="native-settings-actions">
              <button
                className="secondary-button"
                disabled={saving || !snapshot?.preferences.notifications}
                onClick={() => void testNotification()}
              >
                Test notification
              </button>
              {platform === "android" && <button className="secondary-button" onClick={() => void invoke("android_notification_settings")}>Android notification settings</button>}
            </div>
          </div>
          {platform === "android" && snapshot?.notification_permission === "denied" && <p>Android is hiding SirinVPN notifications. The VPN can still run; use the Quick Settings tile or this app to control it.</p>}
        </>}
        {row(
          "animations",
          "Interface animations",
          "Subtle transitions between pages and panels. Your system's reduced-motion setting takes priority.",
        )}
      </section>
      {onCheckUpdates && (
        <section className="settings-card settings-action-row">
          <div>
            <h2>App updates</h2>
            <p>Check for a verified update when you're ready.</p>
          </div>
          <button className="secondary-button" onClick={onCheckUpdates}>
            <ArrowClockwise size={17} /> App updates
          </button>
        </section>
      )}
      {platform === "desktop" && onReviewComponentUpdate && <section className="settings-card settings-action-row">
        <div><h2>Local VPN component</h2><p>Keep this computer's VPN service compatible with the app.</p></div>
        <button className="secondary-button" onClick={onReviewComponentUpdate}>Review local component</button>
      </section>}
      {!changedKey && (
        <p className="preferences-status" role="status">
          {loading
            ? "Loading preferences…"
            : saving
              ? "Saving…"
              : status || "Preferences are saved on this device."}
        </p>
      )}
    </div>
  );
}

function QuickProfile() {
  const [profiles, setProfiles] = useState<ServerProfile[]>([]);
  const [selected, setSelected] = useState("");
  const [error, setError] = useState("");
  useEffect(() => {
    let active = true;
    void Promise.all([api.listServers(), invoke<{ quick_profile: string | null }>("android_snapshot")]).then(([list, state]) => {
      if (active) { setProfiles(list); setSelected(state.quick_profile ?? ""); }
    }).catch(() => { if (active) setError("Quick-connect profiles could not be read."); });
    return () => { active = false; };
  }, []);
  return <label className="field"><span>Quick Settings connection</span><select value={selected} disabled={!profiles.length}
    onChange={event => { const id = event.target.value; void invoke("android_set_quick_profile", { serverId: id }).then(() => { setSelected(id); setError(""); }).catch(() => setError("The quick-connect choice was not saved.")); }}>
    <option value="" disabled>Choose a saved server</option>{profiles.map(profile => <option key={profile.id} value={profile.id}>{profile.name}</option>)}
  </select>{error && <span role="alert">{error}</span>}</label>;
}
