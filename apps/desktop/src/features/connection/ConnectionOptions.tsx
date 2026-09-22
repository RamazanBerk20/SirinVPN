import { invoke, isAndroid } from "../../platform";
import { Check, CaretDown } from "@phosphor-icons/react";
import type { ServerWorkspaceModel } from "./useServerWorkspace";
import type { TransportPreference, NetworkProfile } from "../../types";
import { describeConnection } from "./connectionState";
import { formatTransport } from "../../format";
import { StartupConnectionState } from "./StartupConnectionState";
import { PreferenceSaveBar } from "./PreferenceSaveBar";
import { MtuSettings } from "./MtuSettings";

const conditions: { value: NetworkProfile; title: string; hint: string }[] = [
  {
    value: "automatic",
    title: "Auto",
    hint: "Automatically choose a working method",
  },
  {
    value: "normal",
    title: "Normal",
    hint: "An ordinary home or mobile network",
  },
  {
    value: "restricted",
    title: "Restricted",
    hint: "A network that blocks regular VPN traffic",
  },
  {
    value: "extreme",
    title: "Heavily restricted",
    hint: "A network where other modes fail",
  },
];
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
  const transports: {
    value: TransportPreference;
    title: string;
    hint: string;
    unavailable?: boolean;
  }[] = [
    { value: "direct_udp", title: "Direct UDP", hint: "Standard WireGuard" },
    {
      value: "obfuscated_udp",
      title: "Obfuscated UDP",
      hint: "Authenticated UDP wrapper",
      unavailable: !profile.obfuscated_udp,
    },
    {
      value: "tls_like",
      title: "TLS fallback",
      hint: "Pinned TLS 1.3",
      unavailable: !profile.tls_like,
    },
    {
      value: "tcp_fallback",
      title: "TCP fallback",
      hint: "Authenticated TCP · last resort",
      unavailable: !profile.tcp_fallback,
    },
  ];
  const choose = (value: TransportPreference) => {
    setSelectedTransport(value);
  };
  return (
    <div className="settings-sections connection-preferences">
      <PreferenceSaveBar
        preferences={model.preferences}
        local={model.localStatus}
        serverId={profile.id}
      />
      <section className="settings-card">
        <h2>Saved connection preferences</h2>
        <p>Connection preferences for this device on {profile.name}.</p>
        <label className="preference-row">
          <span>
            <strong>Choose transport automatically</strong>
            <small>
              Find a working method for the network conditions below.
            </small>
          </span>
          <input
            type="checkbox"
            role="switch"
            aria-label="Choose transport automatically"
            checked={selectedTransport === "automatic"}
            disabled={disabled}
            onChange={(e) =>
              choose(e.target.checked ? "automatic" : "direct_udp")
            }
          />
        </label>
        {selectedTransport === "automatic" ? (
          <fieldset className="choice-fieldset">
            <legend>Network conditions</legend>
            <div className="condition-choices">
              {conditions.map(({ value, title, hint }) => (
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
                    <strong>{title}</strong>
                    <small>{hint}</small>
                  </span>
                  {selectedNetworkProfile === value && (
                    <Check size={18} aria-hidden="true" />
                  )}
                </label>
              ))}
            </div>
            <p className="settings-note">
              Every mode uses encrypted, authenticated connections.
            </p>
          </fieldset>
        ) : (
          <fieldset className="choice-fieldset">
            <legend>Manual transport</legend>
            <div className="condition-choices">
              {transports.map(({ value, title, hint, unavailable }) => (
                <label className="choice-row" key={value}>
                  <input
                    type="radio"
                    name="manual-transport"
                    checked={selectedTransport === value}
                    disabled={disabled || unavailable}
                    onChange={() => choose(value)}
                  />
                  <span>
                    <strong>{title}</strong>
                    <small>
                      {unavailable
                        ? "Update the VPS to enable this transport"
                        : hint}
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
        {(
          [
            [
              "kill_switch",
              "Kill switch",
              "Block traffic outside the VPN if this connection fails. Disconnect releases the block.",
            ],
            [
              "automatic_reconnect",
              "Automatic reconnect",
              "Retry an interrupted connection. This does not change your kill switch preference.",
            ],
            [
              "connect_on_startup",
              "Connect on system startup",
              "Start this VPN when the device boots. Manual Disconnect deactivates startup and keeps this preference saved.",
            ],
          ] as const
        ).filter(([key]) => !isAndroid || key === "automatic_reconnect").map(([key, label, hint]) => (
          <label className="preference-row" key={key}>
            <span>
              <strong>{label}</strong>
              <small>{isAndroid && key === "automatic_reconnect" ? "Saves immediately. Turning this off stops pending reconnect attempts. Android Always-on remains controlled in VPN settings." : hint}</small>
            </span>
            <input
              type="checkbox"
              role="switch"
              aria-label={label}
              checked={connectionPolicy[key]}
              disabled={isAndroid && key === "automatic_reconnect" ? model.preferences.saving || !model.preferences.ready : disabled}
              onChange={(e) => isAndroid && key === "automatic_reconnect"
                ? void model.preferences.setReconnect(e.target.checked)
                : setConnectionPolicy(key, e.target.checked)}
            />
          </label>
        ))}
        {isAndroid ? <div className="settings-action-row"><p>Always-on VPN and Block connections without VPN are Android settings. Blocking remains active until you change it in Android, including after disconnecting.</p><button className="secondary-button" onClick={() => void invoke("android_vpn_settings")}>Android VPN settings</button></div> : <StartupConnectionState model={model} />}
        <p className="settings-note">
          {isAndroid ? "Automatic reconnect is saved and applied immediately. Other connection preferences apply when you connect again." : "Saved per server on this device. Changes apply when you connect again."}
          {" "}Opening another server does not change the active connection.
        </p>
        <details className="inline-disclosure">
          <summary>How automatic selection and recovery work</summary>
          <p>
            Connect tries each available method once. After that, or after a
            connected session fails, only Automatic reconnect permits further
            attempts. The kill switch remains independent throughout.
          </p>
        </details>
        {model.routingMode === "selected_routes" && (
          <p className="settings-note">
            Protection applies to selected routes and system DNS. Other
            destinations continue to use your normal network.
          </p>
        )}
        {!isAndroid && model.routingMode === "selected_applications" && <p className="settings-note">{model.localStatus.application_routing_backend === "windows_bind_redirect"
          ? "Windows application routing requires the kill switch on and local-network access off. Selected executables stay blocked outside the tunnel until Disconnect. System DNS uses the VPS."
          : "Launched apps always lose internet access when the tunnel is unavailable. Other apps and system DNS use their usual network."}</p>}
      </section>
      <MtuSettings model={model} />
      <details className="metrics-details">
        <summary>
          Current status <CaretDown className="disclosure-chevron" size={17} />
        </summary>
        <dl>
          <div>
            <dt>Transport</dt>
            <dd>
              {current.active
                ? formatTransport(model.localStatus.transport)
                : current.status}
            </dd>
          </div>
          <div>
            <dt>Kill switch</dt>
            <dd>{current.protection}</dd>
          </div>
          <div>
            <dt>Routing</dt>
            <dd>{current.routing}</dd>
          </div>
        </dl>
      </details>
    </div>
  );
}
