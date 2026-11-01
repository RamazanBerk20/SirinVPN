import { ArrowClockwise, Power } from "@phosphor-icons/react";
import { useEffect, useRef } from "react";
import { dpadOnly, invoke, isAndroid } from "../../platform";
import { SirinMark } from "../../components/Brand";
import { InlineError } from "../../components/ui";
import type { Page } from "../../components/Navigation";
import { formatTransport, formatLatency } from "../../format";
import { describeConnection } from "./connectionState";
import { InfoHint } from "../../components/InfoHint";
import { t } from "../../i18n";
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
  const power = useRef<HTMLButtonElement>(null);
  // D-pad only: Home starts on this button, and it takes focus back after being disabled while busy.
  useEffect(() => { if (dpadOnly && document.activeElement === document.body) power.current?.focus(); });
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
      aria-label={t("home.consoleLabel")}
    >
      <div className="connection-center">
        {!isAndroid && <SirinMark className="connection-mark" />}
        <button
          className={`power-control ${state.connected ? "active" : ""}`}
          ref={power}
          disabled={busy || state.other}
          aria-label={systemControlled ? t("home.action.androidVpnSettings") : busy ? t("home.action.changing") : state.action}
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
            {systemControlled ? t("home.action.vpnSettings") : busy ? t("home.action.wait") : state.active ? t("home.action.disconnect") : state.action}
          </span>
        </button>
        <p className="connection-state" role="status">
          {busy
            ? t("home.status.changing")
            : state.connected && !state.recoveringAuthorization && !isAndroid ? t("home.status.connectedTo", { name: profile.name }) : state.status}
        </p>
        {!systemControlled && (model.connectionOperation === "connecting" || !state.known) && <button className="secondary-button" type="button" onClick={() => void model.cancelConnection()} disabled={model.connectionOperation === "disconnecting"}>{t("home.action.stop")}</button>}
      </div>
      <p className="connection-explanation">{state.summary}</p>
      {state.active && localStatus.kill_switch_enabled && (
        <p className="disconnect-consequence">
          {t(isAndroid ? "home.consequence.android" : "home.consequence.desktop")}
        </p>
      )}
      {state.active && localStatus.waiting_for_user && (
        <>
        <button
          className="secondary-button"
          onClick={() => void model.resume()}
          disabled={busy}
          title={t("home.action.reconnectHint")}
        >
          {t("home.action.reconnect")}
        </button>
        </>
      )}
      {state.warning && <InlineError message={state.warning} />}
      {!isAndroid && <ConnectionDetails model={model} />}
      {model.presharedKeyMissing && <div className="measurement-update">
        <p>{t("home.presharedKey.missing")}</p>
        <button className="text-button" disabled={busy} onClick={() => model.setRotationOpen(true)}>{t("home.presharedKey.add")}</button>
      </div>}
      {componentUpdateRequired && onReviewComponentUpdate && <div className="measurement-update">
        <p>{t("home.componentUpdate.needed")}</p>
        <button className="text-button" disabled={busy} onClick={onReviewComponentUpdate}>{t("home.componentUpdate.review")}</button>
      </div>}
      {error && <InlineError message={error} />}
      {!state.connected && (error || localStatus.server_id === profile.id && localStatus.state === "degraded") && (
        <button className="text-button" disabled={busy} onClick={() => model.setTroubleshootOpen(true)}>{t("help.troubleshoot.open")}</button>
      )}
    </section>
  );
}

export function ConnectionDetails({ model }: { model: ServerWorkspaceModel }) {
  const { localStatus, profile, serverStatus } = model;
  const state = describeConnection(localStatus, profile.id, serverStatus, model.preferences.saved?.policy);
  return <>
      <dl className="connection-facts">
        <div>
          <dt>{t("home.details.method")}</dt>
          <dd>
            {state.active
              ? formatTransport(localStatus.transport)
              : t(state.known ? "home.routing.inactive" : "common.state.unknown")}
          </dd>
        </div>
        <div>
          <dt>{t("home.details.routing")}</dt>
          <dd>{state.routing}</dd>
        </div>
        <div>
          <dt>{t("home.details.killSwitch")}</dt>
          <dd
            className={state.protectionState === "off" ? "protection-off" : ""}
          >
            {state.protection}
            {state.protectionDetail && (
              <small className="protection-evidence">
                {state.protectionDetail}
              </small>
            )}
          </dd>
        </div>
        {state.applicationIsolation && <div><dt>{t("home.details.appIsolation")}</dt><dd>{state.applicationIsolation}</dd></div>}
        {state.connected && serverStatus?.management_latency_ms !== undefined && (
          <div>
            <dt>{t("home.details.serverResponse")}<InfoHint text={t("home.details.serverResponseInfo")} /></dt>
            <dd>{formatLatency(serverStatus.management_latency_ms)}</dd>
          </div>
        )}
      </dl>
      {state.connected && <p className="settings-note connection-evidence">{t("home.details.reachabilityLine", { state: state.health.reachability })}{state.health.detail && ` ${state.health.detail}`}</p>}
  </>;
}
