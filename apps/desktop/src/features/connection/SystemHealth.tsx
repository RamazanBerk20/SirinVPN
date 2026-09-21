import { TransportQuality } from "./TransportQuality";
import { protectionEvidence } from "./protectionEvidence";
import { mtuDescription } from "./MtuSettings";
import { describeConnection } from "./connectionState";
import type { ServerWorkspaceModel } from "./useServerWorkspace";

export function SystemHealth({
  model,
}: {
  model: ServerWorkspaceModel;
}) {
  const { localStatus: local, profile, serverStatus: remote } = model;
  const state = describeConnection(
    local,
    profile.id,
    remote,
    model.preferences.saved?.policy,
  );
  return (
    <section className="settings-card system-health" aria-label="System health">
      <div className="settings-section-heading">
        <h2>System health</h2>
      </div>
      <dl className="health-checks">
        <div>
          <dt>Local tunnel</dt>
          <dd>{state.status}</dd>
        </div>
        <div>
          <dt>Kill switch</dt>
          <dd>{state.protection}</dd>
        </div>
        <div>
          <dt>Automatic reconnect</dt>
          <dd>
            {!state.known
              ? "Unknown"
              : state.other
                ? "See active server"
                : state.active && local.auto_reconnect_enabled
                  ? "Configured"
                  : "Off"}
          </dd>
        </div>
        <div>
          <dt>Management service</dt>
          <dd>
            {remote
              ? "Responding"
              : state.connected
                ? "Unavailable · VPN remains connected"
                : "Not checked"}
          </dd>
        </div>
        {remote && (
          <>
            <div>
              <dt>Server VPN interface</dt>
              <dd>{remote.interface_up ? "Up" : "Down"}</dd>
            </div>
            <div>
              <dt>Server DNS service</dt>
              <dd>{remote.dns_healthy ? "Running" : "Not responding"}</dd>
            </div>
          </>
        )}
      </dl>
      {local.server_id === profile.id && <TransportQuality status={local} />}
      {local.server_id === profile.id && local.mtu && <p className="settings-note">{mtuDescription(local.mtu)}</p>}
      <p className="settings-note">
        {state.active && local.kill_switch_enabled
          ? protectionEvidence(local).detail
          : state.summary}
      </p>
      <div className="settings-action-row">
        <p>
          Check the local connection, protection, transport and MTU. A connected VPN also enables private DNS and authenticated VPS checks.
        </p>
        <button
          className="secondary-button"
          onClick={() => void model.runDiagnostics()}
        >
          Run diagnostics
        </button>
      </div>
    </section>
  );
}
