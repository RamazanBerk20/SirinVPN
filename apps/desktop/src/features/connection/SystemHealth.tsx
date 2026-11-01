import { TransportQuality } from "./TransportQuality";
import { protectionEvidence } from "./protectionEvidence";
import { describeConnection } from "./connectionState";
import { t } from "../../i18n";
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
    <section className="settings-card system-health" aria-label={t("maintenance.health.title")}>
      <div className="settings-section-heading">
        <h2>{t("maintenance.health.title")}</h2>
      </div>
      <dl className="health-checks">
        <div>
          <dt>{t("maintenance.health.connection")}</dt>
          <dd>{state.status}</dd>
        </div>
        <div>
          <dt>{t("maintenance.health.killSwitch")}</dt>
          <dd>{state.protection}</dd>
        </div>
        <div>
          <dt>{t("maintenance.health.autoReconnect")}</dt>
          <dd>
            {!state.known
              ? t("common.state.unknown")
              : state.other
                ? t("maintenance.health.autoReconnectOther")
                : state.active && local.auto_reconnect_enabled
                  ? t("common.state.enabled")
                  : t("common.state.disabled")}
          </dd>
        </div>
        <div>
          <dt>{t("maintenance.health.management")}</dt>
          <dd>
            {remote
              ? t("maintenance.health.managementResponding")
              : state.connected
                ? t("maintenance.health.managementUnavailable")
                : t("maintenance.health.notChecked")}
          </dd>
        </div>
        {remote && (
          <>
            <div>
              <dt>{t("maintenance.health.serverVpn")}</dt>
              <dd>{remote.interface_up ? t("maintenance.health.serverVpnUp") : t("maintenance.health.serverVpnDown")}</dd>
            </div>
            <div>
              <dt>{t("maintenance.health.serverDns")}</dt>
              <dd>{remote.dns_healthy ? t("maintenance.health.serverDnsRunning") : t("maintenance.health.serverDnsDown")}</dd>
            </div>
          </>
        )}
      </dl>
      {local.server_id === profile.id && <TransportQuality status={local} />}
      {state.active && local.kill_switch_enabled && <p className="settings-note">{protectionEvidence(local).detail}</p>}
      <div className="settings-action-row">
        <p>{t("maintenance.health.diagnosticsSummary")}</p>
        <button
          className="secondary-button"
          onClick={() => void model.runDiagnostics()}
        >
          {t("maintenance.health.runDiagnostics")}
        </button>
      </div>
      <div className="settings-action-row">
        <p>{t("help.troubleshoot.settingsSummary")}</p>
        <button className="secondary-button" onClick={() => model.setTroubleshootOpen(true)}>
          {t("help.troubleshoot.settingsAction")}
        </button>
      </div>
    </section>
  );
}
