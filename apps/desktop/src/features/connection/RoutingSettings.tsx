import { Check } from "@phosphor-icons/react";
import type { ServerWorkspaceModel } from "./useServerWorkspace";
import { PreferenceSaveBar } from "./PreferenceSaveBar";
import { ApplicationLauncher } from "./ApplicationLauncher";
import { invoke, isAndroid } from "../../platform";
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
  const disabled =
    model.busy || model.preferences.saving || !model.preferences.ready;
  const windows = model.localStatus.application_routing_backend === "windows_bind_redirect";
  return (
    <section className="settings-card routing-settings">
      <h2>Traffic routing · next connection</h2>
      <p>Routing preferences for this device on {profile.name}.</p>
      <PreferenceSaveBar
        preferences={model.preferences}
        local={model.localStatus}
        serverId={profile.id}
      />
      <fieldset className="choice-fieldset">
        <legend>Routing mode</legend>
        <div className="condition-choices">
          {(
            [
              {
                value: "full_tunnel",
                label: "Full tunnel",
                hint: "Route internet destinations through the VPS",
              },
              {
                value: "selected_routes",
                label: "Selected routes",
                hint: "Route only the IP ranges you specify",
              },
              {
                value: "selected_applications",
                label: "Selected applications",
                hint: isAndroid ? "Choose which Android applications use the VPN" : windows ? "Route selected Windows executables through the VPS" : "Only applications launched through SirinVPN use this connection",
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
              {routingMode === value && <Check size={18} aria-hidden="true" />}
            </label>
          ))}
        </div>
      </fieldset>
      {model.localStatus.application_routing_supported !== true && <p className="settings-note">{windows
        ? "Application routing is unavailable because its signed Windows driver is not running. Repair or update the installation."
        : "This VPN component does not support application routing. IP and subnet rules remain available."}</p>}
      {windows && routingMode === "selected_applications" && <p className="settings-note">Enable the kill switch in Connection settings and turn local-network access off before connecting.</p>}
      {!windows && !isAndroid && routingMode === "selected_applications" && <p className="settings-note">Already-running processes are unaffected. Other applications keep their normal network connection.</p>}
      {isAndroid && routingMode === "selected_applications" && <div>
        <p>Android applies the selected packages on the next connection. With Block connections without VPN, excluded apps lose network access.</p>
        <button className="secondary-button" disabled={disabled} onClick={() => void invoke<import("./connectionPreferences").ConnectionPreferences["android_applications"]>("android_choose_applications", { selection: model.preferences.draft.android_applications }).then(selection => { if (selection) model.preferences.change({ android_applications: selection }); })}>Choose applications</button>
        <p>{model.preferences.draft.android_applications?.packages.length ?? 0} applications selected · {model.preferences.draft.android_applications?.mode ?? "include"}</p>
      </div>}
      {routingMode === "selected_routes" && (
        <label className="route-list-field">
          <span>IPv4 or IPv6 CIDRs · one per line</span>
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
          />
          <small>
            System DNS always uses the VPS. Unlisted destinations bypass it. Up
            to 32 canonical CIDRs.
          </small>
        </label>
      )}
      <label className="preference-row">
        <span>
          <strong>Allow local network</strong>
          <small>
            {windows && routingMode === "selected_applications" ? "Turn this off for Windows application routing."
              : routingMode === "selected_applications" && !isAndroid
              ? "Allow launched apps to reach IPv4 private, link-local and multicast ranges. Their DNS still uses the VPN."
              : "When enabled, private, link-local, and multicast ranges bypass the VPN."}
          </small>
        </span>
        <input
          type="checkbox"
          role="switch"
          aria-label="Allow local network"
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
