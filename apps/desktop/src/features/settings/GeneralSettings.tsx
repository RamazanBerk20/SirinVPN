import { WifiSettings } from "./WifiSettings";
import { CredentialStorage } from "./CredentialStorage";
import { dpadOnly, invoke } from "../../platform";
import { useCallback, useEffect, useState, type ReactNode } from "react";
import { api } from "../../api";
import type { ServerProfile } from "../../types";
import { ArrowClockwise, Bell, Desktop } from "@phosphor-icons/react";
import { InlineError } from "../../components/ui";
import { notify } from "../../components/Toasts";
import type { ClientPlatform } from "../../types";
import type { AppPreferences } from "./preferences";
import { usePreferences } from "./PreferencesProvider";
import { t } from "../../i18n";
import { useInfoHint } from "../../components/InfoHint";
import { SettingsNotice } from "./SettingsParts";

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
  const android = platform === "android";
  const denied = snapshot?.notification_permission === "denied";
  /** Each result sits next to the control that caused it. */
  const feedback = (key: keyof AppPreferences | "test"): ReactNode => {
    if (changedKey !== key) return null;
    if (error) return <InlineError message={error} />;
    return (saving || status) ? <small className="preference-feedback" role="status">{saving ? t("common.state.saving") : status}</small> : null;
  };
  const row = (
    key: Exclude<keyof AppPreferences, "theme">,
    label: string,
    description: string,
    unavailable = false,
    extra?: ReactNode,
  ) => (
    <div className="preference-group">
      <label className="preference-row">
        <span>
          <strong>{label}</strong>
          <small>{description}</small>
          {changedKey === key && !error && feedback(key)}
        </span>
        <input
          type="checkbox"
          role="switch"
          aria-label={label}
          // Notifications the system blocks are off, whatever was saved.
          checked={(snapshot?.preferences[key] ?? false) && !(key === "notifications" && (android ? snapshot?.notification_permission !== "granted" : denied))}
          disabled={loading || saving || !snapshot || unavailable}
          onChange={(event) => void change(key, event.target.checked)}
        />
      </label>
      {changedKey === key && error && feedback(key)}
      {extra}
    </div>
  );
  // Until app preferences load, their switches would show defaults as if saved: show the load state instead.
  const pending = !snapshot && <section className="settings-card" aria-busy={loading}>
    {error && !loading
      ? <InlineError message={error} onRetry={() => void refresh()} />
      : <p role="status">{t("settings.general.loading")}</p>}
  </section>;
  return (
    <div className="settings-sections" aria-busy={loading || saving}>
      {pending}
      {snapshot && platform === "desktop" && (
        <section className="settings-card">
          <div className="settings-section-heading">
            <Desktop size={21} />
            <h2>{t("settings.general.startup.title")}</h2>
          </div>
          {row(
            "start_on_login",
            t("settings.general.startup.startOnLogin.label"),
            !snapshot.startup_available
              ? t("settings.general.startup.startOnLogin.unavailable")
              : t("settings.general.startup.startOnLogin.summary"),
            !snapshot.startup_available,
          )}
          {row(
            "launch_minimized",
            t("settings.general.startup.launchMinimized.label"),
            t("settings.general.startup.launchMinimized.summary"),
          )}
          {row(
            "close_to_tray",
            t("settings.general.startup.closeToTray.label"),
            !snapshot.tray_available
              ? t("settings.general.startup.closeToTray.unavailable")
              : t("settings.general.startup.closeToTray.summary"),
            !snapshot.tray_available,
          )}
          <p className="settings-note">{t("settings.general.startup.note")}</p>
        </section>
      )}
      {/* A TV never changes Wi-Fi and usually has no location provider to reveal its name. */}
      {!dpadOnly && <WifiSettings />}
      {platform === "desktop" && <CredentialStorage />}
      {android && <section className="settings-card">
        <h2>{t("settings.general.android.title")}</h2>
        <p>{t("settings.general.android.summary")}</p>
        <QuickProfile />
        <div className="settings-action-row"><button className="secondary-button" onClick={() => void invoke("android_vpn_settings")}>{t("settings.general.android.vpnSettings")}</button>
        <button className="secondary-button" onClick={() => void invoke<unknown>("android_add_tile")
          .then(value => setTileMessage(typeof value === "string" ? value : ""))
          .catch(() => setTileMessage(t("settings.general.android.addTileManually")))}>{t("settings.general.android.addTile")}</button></div>
        {tileMessage && <p role="status">{tileMessage}</p>}
      </section>}
      {snapshot && <section className="settings-card">
        <div className="settings-section-heading">
          <Bell size={21} />
          <h2>{t("settings.general.notifications.title")}</h2>
          {notificationInfo}
        </div>
        {notificationInfoPanel}
        {row(
          "notifications",
          t("settings.general.notifications.connection.label"),
          t("settings.general.notifications.connection.summary"),
          false,
          <>
            {denied && <SettingsNotice tone="warning"
              action={android ? { label: t("settings.general.notifications.androidSettings"), onClick: () => void invoke("android_notification_settings") } : undefined}>
              {t(android ? "settings.general.notifications.blockedAndroid" : "settings.general.notifications.blocked")}
            </SettingsNotice>}
            <div className="preference-actions">
              <button
                className="secondary-button"
                disabled={saving || !snapshot.preferences.notifications}
                onClick={() => void testNotification()}
              >
                {changedKey === "test" && saving ? t("settings.general.notifications.testing") : t("settings.general.notifications.test")}
              </button>
              {/* The reason sits right under the button it disables. */}
              {!snapshot.preferences.notifications && <small>{t("settings.general.notifications.testNeedsNotifications")}</small>}
              {android && !denied && <button className="secondary-button" onClick={() => void invoke("android_notification_settings")}>{t("settings.general.notifications.androidSettings")}</button>}
              {changedKey === "test" && !saving && feedback("test")}
            </div>
          </>,
        )}
        {row(
          "animations",
          t("settings.general.notifications.animations.label"),
          t("settings.general.notifications.animations.summary"),
        )}
        <div className="preference-group">
          <div className="preference-row" role="group" aria-labelledby="theme-preference-label">
            <span>
              <strong id="theme-preference-label">{t("settings.general.notifications.theme.label")}</strong>
              <small>{t("settings.general.notifications.theme.summary")}</small>
              {changedKey === "theme" && !error && feedback("theme")}
            </span>
            <div className="segmented-control theme-choice">
              {(["system", "light", "dark"] as const).map((theme) => (
                <button
                  key={theme}
                  type="button"
                  aria-pressed={snapshot.preferences.theme === theme}
                  disabled={loading || saving}
                  onClick={() => void change("theme", theme)}
                >
                  {t(`settings.general.notifications.theme.${theme}`)}
                </button>
              ))}
            </div>
          </div>
          {changedKey === "theme" && error && feedback("theme")}
        </div>
      </section>}
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
    </div>
  );
}

function QuickProfile() {
  const [profiles, setProfiles] = useState<ServerProfile[]>([]);
  const [selected, setSelected] = useState("");
  const [error, setError] = useState<{ message: string; retry: () => void } | null>(null);
  const load = useCallback((active: () => boolean = () => true) => {
    setError(null);
    void Promise.all([api.listServers(), invoke<{ quick_profile: string | null }>("android_snapshot")]).then(([list, state]) => {
      if (active()) { setProfiles(list); setSelected(state.quick_profile ?? ""); }
    }).catch(() => { if (active()) setError({ message: t("settings.general.quickServer.loadFailed"), retry: () => load() }); });
  }, []);
  useEffect(() => {
    let active = true;
    load(() => active);
    return () => { active = false; };
  }, [load]);
  const choose = (id: string) => {
    setError(null);
    void invoke("android_set_quick_profile", { serverId: id })
      .then(() => { setSelected(id); notify(t("settings.general.quickServer.saved", { name: profiles.find((profile) => profile.id === id)?.name ?? "" })); })
      .catch(() => setError({ message: t("settings.general.quickServer.saveFailed"), retry: () => choose(id) }));
  };
  return <div className="quick-profile">
    <label className="field"><span>{t("settings.general.quickServer.label")}</span><select value={selected} disabled={!profiles.length}
      onChange={event => choose(event.target.value)}>
      <option value="" disabled>{t("settings.general.quickServer.placeholder")}</option>{profiles.map(profile => <option key={profile.id} value={profile.id}>{profile.name}</option>)}
    </select></label>
    {error && <InlineError message={error.message} onRetry={error.retry} />}
  </div>;
}
