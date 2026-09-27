import { ArrowClockwise, Power } from "@phosphor-icons/react";
import { invoke, isAndroid } from "../../platform";
import { SirinMark } from "../../components/Brand";
import { InlineError } from "../../components/ui";
import type { Page } from "../../components/Navigation";
import { formatTransport, formatLatency } from "../../format";
import { describeConnection } from "./connectionState";
import type { ServerWorkspaceModel } from "./useServerWorkspace";

export function ConnectionHero({
  model,
  view,
  onReviewComponentUpdate,
}: {
  model: ServerWorkspaceModel;
  view: Page;
  onReviewComponentUpdate?: () => void;
}) {
  if (view !== "home") return null;
  const { localStatus, profile, serverStatus, busy, error } = model;
  const systemControlled = isAndroid && localStatus.always_on === true;
  const state = describeConnection(
    localStatus,
    profile.id,
    serverStatus,
    model.preferences.saved?.policy,
  );
  const componentUpdateRequired = !isAndroid && state.known && (
    localStatus.mtu_detection_supported === false ||
    localStatus.endpoint_updates_supported === false
  );
  return (
    <section
      className={`connection-console ${state.connected && !state.recoveringAuthorization ? "is-connected" : ""}`}
      aria-label="VPN connection"
    >
      <div className="connection-center">
        {!isAndroid && <SirinMark className="connection-mark" />}
        <button
          className={`power-control ${state.connected ? "active" : ""}`}
          disabled={busy || state.other}
          aria-label={systemControlled ? "Android VPN settings" : busy ? "Changing connection" : state.action}
          onClick={() =>
            void (systemControlled ? invoke("android_vpn_settings") : componentUpdateRequired && !state.active && onReviewComponentUpdate
              ? onReviewComponentUpdate()
              : state.known ? model.toggle() : model.onRefresh())
          }
        >
          {busy ? (
            <ArrowClockwise size={36} className="spin" />
          ) : (
            <Power size={36} />
          )}
          <span>
            {systemControlled ? "VPN settings" : busy ? "Please wait…" : state.active ? "Disconnect" : state.action}
          </span>
        </button>
        <p className="connection-state" role="status">
          {busy
            ? "Changing connection…"
            : `${state.status}${state.connected && !state.recoveringAuthorization && !isAndroid ? ` to ${profile.name}` : ""}`}
        </p>
        {!systemControlled && (model.connectionOperation === "connecting" || !state.known) && <button className="secondary-button" type="button" onClick={() => void model.cancelConnection()} disabled={model.connectionOperation === "disconnecting"}>Stop VPN</button>}
      </div>
      <p className="connection-explanation">{state.summary}</p>
      {state.active && localStatus.kill_switch_enabled && (
        <p className="disconnect-consequence">
          {isAndroid ? "Android controls traffic blocking. Change Always-on VPN or Block connections without VPN in Android settings." : "Disconnect also releases the traffic block and stops automatic reconnect."}
        </p>
      )}
      {state.active && localStatus.waiting_for_user && (
        <>
        <button
          className="secondary-button"
          onClick={() => void model.resume()}
          disabled={busy}
          title="Resume the active connection policy. Saved changes apply after Disconnect and Connect."
        >
          Reconnect
        </button>
        {isAndroid && <p className="settings-note">Reconnect resumes the active policy. Saved changes apply after Disconnect and Connect.</p>}
        </>
      )}
      {state.warning && <InlineError message={state.warning} />}
      {!isAndroid && <ConnectionDetails model={model} />}
      {componentUpdateRequired && onReviewComponentUpdate && <div className="measurement-update">
        <p>The local VPN component needs updating before this app can connect.</p>
        <button className="text-button" disabled={busy} onClick={onReviewComponentUpdate}>Review local component update</button>
      </div>}
      {error && <InlineError message={error} />}
    </section>
  );
}

export function ConnectionDetails({ model }: { model: ServerWorkspaceModel }) {
  const { localStatus, profile, serverStatus } = model;
  const state = describeConnection(localStatus, profile.id, serverStatus, model.preferences.saved?.policy);
  return <>
      <dl className="connection-facts">
        <div>
          <dt>Transport</dt>
          <dd>
            {state.active
              ? formatTransport(localStatus.transport)
              : state.known
                ? "Not active"
                : "Unknown"}
          </dd>
        </div>
        <div>
          <dt>Routing</dt>
          <dd>{state.routing}</dd>
        </div>
        <div>
          <dt>Kill switch</dt>
          <dd
            className={state.protection === "Disabled" ? "protection-off" : ""}
          >
            {state.protection}
            {state.protectionDetail && (
              <small className="protection-evidence">
                {state.protectionDetail}
              </small>
            )}
          </dd>
        </div>
        {state.applicationIsolation && <div><dt>Application isolation</dt><dd>{state.applicationIsolation}</dd></div>}
        {state.connected && serverStatus?.management_latency_ms !== undefined && (
          <div title="Time for an authenticated management status request; not tunnel latency.">
            <dt>Management response</dt>
            <dd>{formatLatency(serverStatus.management_latency_ms)}{isAndroid && <small>Authenticated management request; separate from tunnel latency.</small>}</dd>
          </div>
        )}
      </dl>
      {state.connected && <p className="settings-note connection-evidence">{state.health.reachability}. {state.health.detail}</p>}
  </>;
}
