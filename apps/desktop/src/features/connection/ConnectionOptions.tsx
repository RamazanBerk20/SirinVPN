import { invoke, isAndroid } from "../../platform";
import { Check, CaretDown } from "@phosphor-icons/react";
import type { ServerWorkspaceModel } from "./useServerWorkspace";
import type { TransportPreference, NetworkProfile, TransportKind } from "../../types";
import { describeConnection } from "./connectionState";
import { formatTransport } from "../../format";
import { StartupConnectionState } from "./StartupConnectionState";
import { MtuSettings } from "./MtuSettings";
import { t } from "../../i18n";
import { useInfoHint } from "../../components/InfoHint";
import { Fragment } from "react";

const conditions: NetworkProfile[] = ["automatic", "normal", "restricted", "extreme"];
const policies = ["kill_switch", "automatic_reconnect", "connect_on_startup"] as const;

export function ConnectionOptions({ model }: { model: ServerWorkspaceModel }) {
  const {
    selectedTransport,
    setSelectedTransport,
    selectedNetworkProfile,
    setSelectedNetworkProfile,
    connectionPolicy,
    setConnectionPolicy,
    profile,
  } = model;
  const disabled =
    model.busy || model.preferences.saving || !model.preferences.ready;
  const current = describeConnection(
    model.localStatus,
    profile.id,
    model.serverStatus,
    model.preferences.saved?.policy,
  );
  const [reconnectInfoButton, reconnectInfoPanel] = useInfoHint(
    t(isAndroid ? "connection.options.policy.automatic_reconnect.infoAndroid" : "connection.options.policy.automatic_reconnect.info"),
    t("connection.options.policy.automatic_reconnect.infoLabel"),
  );
  const transports: {
    value: TransportKind;
    unavailable?: boolean;
  }[] = [
    { value: "direct_udp" },
    { value: "obfuscated_udp", unavailable: !profile.obfuscated_udp },
    { value: "tls_like", unavailable: !profile.tls_like },
    { value: "tcp_fallback", unavailable: !profile.tcp_fallback },
  ];
  const choose = (value: TransportPreference) => {
    setSelectedTransport(value);
  };
  return (
    <div className="settings-sections connection-preferences">
      <section className="settings-card">
        <h2>{t("connection.options.title")}</h2>
        <p>{t("connection.scope", { server: profile.name })}</p>
        <label className="preference-row">
          <span>
            <strong>{t("connection.options.automatic.label")}</strong>
            <small>{t("connection.options.automatic.summary")}</small>
          </span>
          <input
            type="checkbox"
            role="switch"
            aria-label={t("connection.options.automatic.label")}
            checked={selectedTransport === "automatic"}
            disabled={disabled}
            onChange={(e) =>
              choose(e.target.checked ? "automatic" : "direct_udp")
            }
          />
        </label>
        {selectedTransport === "automatic" ? (
          <fieldset className="choice-fieldset">
            <legend>{t("connection.options.conditions.legend")}</legend>
            <div className="condition-choices">
              {conditions.map((value) => (
                <label key={value} className="choice-row">
                  <input
                    type="radio"
                    name="network-conditions"
                    value={value}
                    checked={selectedNetworkProfile === value}
                    disabled={disabled}
                    onChange={() => setSelectedNetworkProfile(value)}
                  />
                  <span>
                    <strong>{t(`connection.options.conditions.${value}.title`)}</strong>
                    <small>{t(`connection.options.conditions.${value}.summary`)}</small>
                  </span>
                  {selectedNetworkProfile === value && (
                    <Check size={18} aria-hidden="true" />
                  )}
                </label>
              ))}
            </div>
          </fieldset>
        ) : (
          <fieldset className="choice-fieldset">
            <legend>{t("connection.options.methods.legend")}</legend>
            <div className="condition-choices">
              {transports.map(({ value, unavailable }) => (
                <label className="choice-row" key={value}>
                  <input
                    type="radio"
                    name="manual-transport"
                    checked={selectedTransport === value}
                    disabled={disabled || unavailable}
                    onChange={() => choose(value)}
                  />
                  <span>
                    <strong>{formatTransport(value)}</strong>
                    <small>
                      {unavailable
                        ? t("connection.options.methods.unavailable")
                        : t(`connection.options.methods.summary.${value}`)}
                    </small>
                  </span>
                  {selectedTransport === value && (
                    <Check size={18} aria-hidden="true" />
                  )}
                </label>
              ))}
            </div>
          </fieldset>
        )}
        {policies.filter((key) => !isAndroid || key === "automatic_reconnect").map((key) => {
          const label = t(`connection.options.policy.${key}.label`);
          const androidReconnect = isAndroid && key === "automatic_reconnect";
          return (
            <Fragment key={key}>
              <label className="preference-row">
                <span>
                  <strong>{label}{key === "automatic_reconnect" && reconnectInfoButton}</strong>
                  <small>{androidReconnect ? t("connection.options.policy.automatic_reconnect.summaryAndroid") : t(`connection.options.policy.${key}.summary`)}</small>
                </span>
                <input
                  type="checkbox"
                  role="switch"
                  aria-label={label}
                  checked={connectionPolicy[key]}
                  disabled={androidReconnect ? model.preferences.saving || !model.preferences.ready : disabled}
                  onChange={(e) => androidReconnect
                    ? void model.preferences.setReconnect(e.target.checked)
                    : setConnectionPolicy(key, e.target.checked)}
                />
              </label>
              {key === "automatic_reconnect" && reconnectInfoPanel}
            </Fragment>
          );
        })}
        {isAndroid ? <div className="settings-action-row"><p>{t("connection.options.android.summary")}</p><button className="secondary-button" onClick={() => void invoke("android_vpn_settings")}>{t("connection.options.android.open")}</button></div> : <StartupConnectionState model={model} />}
        {model.routingMode === "selected_routes" && (
          <p className="settings-note">{t("connection.options.notes.selectedRoutes")}</p>
        )}
        {!isAndroid && model.routingMode === "selected_applications" && <p className="settings-note">{model.localStatus.application_routing_backend === "windows_bind_redirect"
          ? t("connection.options.notes.windowsApps")
          : t("connection.options.notes.launchedApps")}</p>}
      </section>
      <MtuSettings model={model} />
      <details className="metrics-details">
        <summary>
          {t("connection.options.status.title")} <CaretDown className="disclosure-chevron" size={17} />
        </summary>
        <dl>
          <div>
            <dt>{t("connection.options.status.method")}</dt>
            <dd>
              {current.active
                ? formatTransport(model.localStatus.transport)
                : current.status}
            </dd>
          </div>
          <div>
            <dt>{t("connection.options.status.killSwitch")}</dt>
            <dd>{current.protection}</dd>
          </div>
          <div>
            <dt>{t("connection.options.status.routing")}</dt>
            <dd>{current.routing}</dd>
          </div>
        </dl>
      </details>
    </div>
  );
}
