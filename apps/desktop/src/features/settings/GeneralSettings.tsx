import { WifiSettings } from "./WifiSettings";
import { CredentialStorage } from "./CredentialStorage";
import { invoke } from "../../platform";
import { useEffect, useState } from "react";
import { api } from "../../api";
import type { ServerProfile } from "../../types";
import { ArrowClockwise, Bell, Desktop } from "@phosphor-icons/react";
import { InlineError } from "../../components/ui";
import type { ClientPlatform } from "../../types";
import type { AppPreferences } from "./preferences";
import { usePreferences } from "./PreferencesProvider";
import { t } from "../../i18n";
import { useInfoHint } from "../../components/InfoHint";

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
  const [notificationInfo, notificationInfoPanel] = useInfoHint(
    t(platform === "android" ? "settings.general.notifications.infoAndroid" : "settings.general.notifications.infoDesktop"),
    t("settings.general.notifications.infoLabel"),
  );
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
            {saving ? t("common.state.saving") : error || status}
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
              {t("common.action.retry")}
            </button>
          )}
        </div>
      )}
      {platform === "desktop" && (
        <section className="settings-card">
          <div className="settings-section-heading">
            <Desktop size={21} />
            <h2>{t("settings.general.startup.title")}</h2>
          </div>
          {row(
            "start_on_login",
            t("settings.general.startup.startOnLogin.label"),
            snapshot && !snapshot.startup_available
              ? t("settings.general.startup.startOnLogin.unavailable")
              : t("settings.general.startup.startOnLogin.summary"),
            !snapshot?.startup_available,
          )}
          {row(
            "launch_minimized",
            t("settings.general.startup.launchMinimized.label"),
            t("settings.general.startup.launchMinimized.summary"),
          )}
          {row(
            "close_to_tray",
            t("settings.general.startup.closeToTray.label"),
            snapshot && !snapshot.tray_available
              ? t("settings.general.startup.closeToTray.unavailable")
              : t("settings.general.startup.closeToTray.summary"),
            !snapshot?.tray_available,
          )}
          <p className="settings-note">{t("settings.general.startup.note")}</p>
        </section>
      )}
      <WifiSettings />
      {platform === "desktop" && <CredentialStorage />}
      {platform === "android" && <section className="settings-card">
        <h2>{t("settings.general.android.title")}</h2>
        <QuickProfile />
        <p>{t("settings.general.android.summary")}</p>
        <div className="settings-action-row"><button className="secondary-button" onClick={() => void invoke("android_vpn_settings")}>{t("settings.general.android.vpnSettings")}</button>
        <button className="secondary-button" onClick={() => void invoke<unknown>("android_add_tile")
          .then(value => setTileMessage(typeof value === "string" ? value : ""))
          .catch(() => setTileMessage(t("settings.general.android.addTileManually")))}>{t("settings.general.android.addTile")}</button></div>
        {tileMessage && <p role="status">{tileMessage}</p>}
      </section>}
      <section className="settings-card">
        <div className="settings-section-heading">
          <Bell size={21} />
          <h2>{t("settings.general.notifications.title")}</h2>
          {notificationInfo}
        </div>
        {notificationInfoPanel}
        {(platform === "desktop" || platform === "android") && <>
          {row(
            "notifications",
            t("settings.general.notifications.connection.label"),
            t("settings.general.notifications.connection.summary"),
          )}
          <div className="settings-action-row">
            <div className="native-settings-actions">
              <button
                className="secondary-button"
                disabled={saving || !snapshot?.preferences.notifications}
                onClick={() => void testNotification()}
              >
                {t("settings.general.notifications.test")}
              </button>
              {platform === "android" && <button className="secondary-button" onClick={() => void invoke("android_notification_settings")}>{t("settings.general.notifications.androidSettings")}</button>}
            </div>
          </div>
          {platform === "android" && snapshot?.notification_permission === "denied" && <p>{t("settings.general.notifications.blockedAndroid")}</p>}
        </>}
        {row(
          "animations",
          t("settings.general.notifications.animations.label"),
          t("settings.general.notifications.animations.summary"),
        )}
      </section>
      {onCheckUpdates && (
        <section className="settings-card settings-action-row">
          <div>
            <h2>{t("settings.general.updates.title")}</h2>
          </div>
          <button className="secondary-button" onClick={onCheckUpdates}>
            <ArrowClockwise size={17} /> {t("settings.general.updates.check")}
          </button>
        </section>
      )}
      {platform === "desktop" && onReviewComponentUpdate && <section className="settings-card settings-action-row">
        <div><h2>{t("settings.general.component.title")}</h2><p>{t("settings.general.component.summary")}</p></div>
        <button className="secondary-button" onClick={onReviewComponentUpdate}>{t("settings.general.component.review")}</button>
      </section>}
      {!changedKey && (
        <p className="preferences-status" role="status">
          {loading
            ? t("common.state.loading")
            : saving
              ? t("common.state.saving")
              : status}
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
    }).catch(() => { if (active) setError(t("settings.general.quickServer.loadFailed")); });
    return () => { active = false; };
  }, []);
  return <label className="field"><span>{t("settings.general.quickServer.label")}</span><select value={selected} disabled={!profiles.length}
    onChange={event => { const id = event.target.value; void invoke("android_set_quick_profile", { serverId: id }).then(() => { setSelected(id); setError(""); }).catch(() => setError(t("settings.general.quickServer.saveFailed"))); }}>
    <option value="" disabled>{t("settings.general.quickServer.placeholder")}</option>{profiles.map(profile => <option key={profile.id} value={profile.id}>{profile.name}</option>)}
  </select>{error && <span role="alert">{error}</span>}</label>;
}
