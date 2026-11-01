import { PreferencesPending } from "./PreferenceSaveBar";
import type { ServerWorkspaceModel } from "./useServerWorkspace";
import { ApplicationLauncher } from "./ApplicationLauncher";
import { invoke, isAndroid } from "../../platform";
import { useState } from "react";
import { InlineError } from "../../components/ui";
import { errorMessage } from "../../lib/errors";
import { formatNumber, t } from "../../i18n";

const MAX_INCLUDED_ROUTES = 32;

export function RoutingSettings({ model }: { model: ServerWorkspaceModel }) {
  const {
    routingMode,
    setRoutingMode,
    includedRoutesDraft,
    setIncludedRoutesDraft,
    allowLan,
    setAllowLan,
    profile,
  } = model;
  const [pickerError, setPickerError] = useState("");
  const disabled =
    model.busy || model.preferences.saving || !model.preferences.ready;
  const windows = model.localStatus.application_routing_backend === "windows_bind_redirect";
  const androidApps = model.preferences.draft.android_applications;
  const androidAppsSummary = !androidApps
    ? t("connection.routing.android.none")
    : androidApps.mode === "all"
      ? t("connection.routing.android.all")
      : androidApps.mode === "exclude"
        ? t("connection.routing.android.exclude", { count: androidApps.packages.length })
        : t("connection.routing.android.include", { count: androidApps.packages.length });
  if (!model.preferences.ready) return <PreferencesPending preferences={model.preferences} />;
  return (
    <section className="settings-card routing-settings">
      <h2>{t("connection.routing.title")}</h2>
      <p>{t("connection.scope", { server: profile.name })}</p>
      <fieldset className="choice-fieldset">
        <legend>{t("connection.routing.legend")}</legend>
        <div className="condition-choices">
          {(
            [
              {
                value: "full_tunnel",
                label: t("connection.routing.modes.full_tunnel.label"),
                hint: t("connection.routing.modes.full_tunnel.summary"),
              },
              {
                value: "selected_routes",
                label: t("connection.routing.modes.selected_routes.label"),
                hint: t("connection.routing.modes.selected_routes.summary"),
              },
              {
                value: "selected_applications",
                label: t("connection.routing.modes.selected_applications.label"),
                hint: isAndroid
                  ? t("connection.routing.modes.selected_applications.summaryAndroid")
                  : windows
                    ? t("connection.routing.modes.selected_applications.summaryWindows")
                    : t("connection.routing.modes.selected_applications.summaryLinux"),
              },
            ] as const
          ).map(({ value, label, hint }) => (
            <label className="choice-row" key={value}>
              <input
                type="radio"
                name="traffic-routing"
                checked={routingMode === value}
                disabled={disabled || (value === "selected_applications" && model.localStatus.application_routing_supported !== true)}
                onChange={() => { setRoutingMode(value); if (isAndroid && value !== "selected_applications") model.preferences.change({ android_applications: null }); }}
              />
              <span>
                <strong>{label}</strong>
                <small>{hint}</small>
              </span>
              
            </label>
          ))}
        </div>
      </fieldset>
      {model.localStatus.application_routing_supported !== true && <p className="settings-note">{windows
        ? t("connection.routing.unsupportedWindows")
        : t("connection.routing.unsupported")}</p>}
      {windows && routingMode === "selected_applications" && <p className="settings-note">{t("connection.routing.windowsKillSwitch")}</p>}
      {isAndroid && routingMode === "selected_applications" && <div>
        <p>{t("connection.routing.android.blockNote")}</p>
        <button className="secondary-button" disabled={disabled} onClick={() => { setPickerError(""); void invoke<import("./connectionPreferences").ConnectionPreferences["android_applications"]>("android_choose_applications", { selection: model.preferences.draft.android_applications }).then(selection => { if (selection) model.preferences.change({ android_applications: selection }); }).catch(reason => setPickerError(errorMessage(reason, t("connection.routing.android.chooseError")))); }}>{t("connection.routing.android.choose")}</button>
        <InlineError message={pickerError} />
        <p>{androidAppsSummary}</p>
      </div>}
      {routingMode === "selected_routes" && (
        <label className="route-list-field">
          <span>{t("connection.routing.routes.label")}</span>
          <textarea
            value={includedRoutesDraft}
            onChange={(e) => setIncludedRoutesDraft(e.target.value)}
            placeholder={
              profile.ipv6_tunnel_enabled
                ? "198.51.100.0/24\n2001:db8:1234::/48"
                : "198.51.100.0/24\n203.0.113.40/32"
            }
            rows={3}
            disabled={disabled}
            aria-invalid={model.preferences.badRoutes.length > 0}
          />
          <small>{t("connection.routing.routes.hint", { max: formatNumber(MAX_INCLUDED_ROUTES) })}</small>
          {model.preferences.badRoutes.length > 0 && <small className="field-error" role="alert">
            {model.preferences.badRoutes[0] === "" ? t("connection.routing.routes.empty") : t("connection.routing.routes.invalid", { routes: model.preferences.badRoutes.join(", ") })}
          </small>}
        </label>
      )}
      <label className="preference-row">
        <span>
          <strong>{t("connection.routing.localNetwork.label")}</strong>
          <small>
            {windows && routingMode === "selected_applications" ? t("connection.routing.localNetwork.summaryWindows")
              : routingMode === "selected_applications" && !isAndroid
              ? t("connection.routing.localNetwork.summaryLaunched")
              : t("connection.routing.localNetwork.summary")}
          </small>
        </span>
        <input
          type="checkbox"
          role="switch"
          aria-label={t("connection.routing.localNetwork.label")}
          checked={allowLan}
          onChange={(e) => setAllowLan(e.target.checked)}
          disabled={disabled}
        />
      </label>
      {!isAndroid && (routingMode === "selected_applications" || (model.localStatus.server_id === profile.id && model.localStatus.routing_mode === "selected_applications")) &&
        <ApplicationLauncher serverId={profile.id} local={model.localStatus} busy={model.busy || model.preferences.saving} />}
    </section>
  );
}
