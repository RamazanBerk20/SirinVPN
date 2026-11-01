const GeneralSettings = lazy(() => import("../settings/GeneralSettings").then(m => ({ default: m.GeneralSettings })));
import {
  SettingsLayout,
  type SettingsCategory,
} from "../settings/SettingsLayout";
import { ConnectionHero } from "./ConnectionHero";
import { ConnectionOptions } from "./ConnectionOptions";
import { ServerMetrics } from "./ServerMetrics";
import { lazy, Suspense, useEffect, useRef, useState } from "react";
import type { DesktopNavigation } from "../../hooks/useDesktopTray";
import { DeviceTraffic, DeviceTrafficDetails } from "./DeviceTraffic";
const LocalComponentUpdate = lazy(() => import("../settings/LocalComponentUpdate").then(m => ({ default: m.LocalComponentUpdate })));
const RoutingSettings = lazy(() => import("./RoutingSettings").then(m => ({ default: m.RoutingSettings })));
const SystemHealth = lazy(() => import("./SystemHealth").then(m => ({ default: m.SystemHealth })));
const MaintenanceTools = lazy(() => import("./MaintenanceTools").then(m => ({ default: m.MaintenanceTools })));
const WorkspaceDialogs = lazy(() => import("./WorkspaceDialogs").then(m => ({ default: m.WorkspaceDialogs })));
import { CopyValue } from "../../components/CopyValue";
import type { Page } from "../../components/Navigation";
const AccessPanel = lazy(() => import("../devices/AccessPanel").then(m => ({ default: m.AccessPanel })));
const VpsAlertSettings = lazy(() => import("../settings/VpsAlertSettings").then(m => ({ default: m.VpsAlertSettings })));
const DnsBlocklistSettings = lazy(() => import("../dns/DnsBlocklistSettings").then(m => ({ default: m.DnsBlocklistSettings })));
const PortForwardSettings = lazy(() => import("../devices/PortForwardSettings").then(m => ({ default: m.PortForwardSettings })));
import { formatDnsPolicy } from "../../format";
import { useServerWorkspace } from "./useServerWorkspace";
import { PreferenceSaveBar } from "./PreferenceSaveBar";
import { isAndroid } from "../../platform";
import { Brand } from "../../components/Brand";
import { ArrowLeft, CaretRight, SlidersHorizontal, Info } from "@phosphor-icons/react";
import { formatTransport } from "../../format";
import { ListRow } from "../../components/ListRow";
import { t } from "../../i18n";
import type { ServerProfile } from "../../types";
import { ServerPicker } from "../servers/ServerPicker";
import { MobileConnectionDetails } from "./MobileConnectionDetails";

export function ServerWorkspace(
  props: Parameters<typeof useServerWorkspace>[0] & {
    view: Page;
    detail?: string;
    onBack?: () => void;
    onOpenSettings: (category: SettingsCategory) => void;
    onCheckUpdates: () => void;
    onNavigate: (page: Page, detail?: string) => void;
    category: SettingsCategory;
    onCategoryChange: (category: SettingsCategory) => void;
    onRestoreDevice: () => void;
    trayRequest?: DesktopNavigation | null;
    onTrayRequestHandled?: () => void;
    servers: ServerProfile[];
    onSelectServer: (id: string) => void;
    onAddServer: () => void;
  },
) {
  const model = useServerWorkspace(props);
  const [componentUpdateOpen, setComponentUpdateOpen] = useState(false);
  const handledTrayRequest = useRef<number | null>(null);
  // Runs outside the lazy boundary and before the tray effect, so a tray request that changes the view keeps its dialog open.
  const { setDiagnosticsOpen } = model;
  useEffect(() => { setDiagnosticsOpen(false); }, [props.view, setDiagnosticsOpen]);
  useEffect(() => {
    const request = props.trayRequest;
    if (!request || handledTrayRequest.current === request.sequence) return;
    handledTrayRequest.current = request.sequence;
    if (request.destination === "diagnostics") void model.runDiagnostics();
    if (request.destination === "component_update")
      setComponentUpdateOpen(true);
    props.onTrayRequestHandled?.();
  }, [props.trayRequest, model.runDiagnostics]);
  const { profile, connected, accessLevel, onAccessChanged } =
    model;
  const { view, category, onCategoryChange } = props;
  const mobileDetails = isAndroid && props.detail === "details";
  const mobileConnection = isAndroid && view === "home" && props.detail === "connection";
  const mobileSubpage = mobileDetails || mobileConnection;
  const scope = category === "general" ? t("app.settingsScope.general") : t(`app.settingsScope.${category}`, { name: profile.name });
  const reviewActivity = () => {
    props.onOpenSettings("maintenance");
    if (model.serverStatus && !model.serverStatus.peer_activity_supported && profile.role === "owner") model.setMaintenanceReview("update");
  };
  return (
    <div
      className={`server-workspace view-${view}`}
      hidden={view === "servers"}
    >
      {isAndroid && view === "home" && (mobileSubpage ?
        <header className="mobile-page-header"><button className="icon-button" aria-label={t("common.action.back")} onClick={props.onBack}><ArrowLeft size={24} /></button><h1>{t(mobileDetails ? "app.home.detailsTitle" : "app.home.connectionTitle")}</h1></header> :
        <header className="mobile-home-header"><Brand compact /></header>)}
      {(!isAndroid || view === "devices" || view === "settings" && !props.detail) && <header className="workspace-header">
        <div>
          <h1>
            {view === "settings"
              ? t("app.nav.settings")
              : view === "devices"
                ? t("app.nav.devices")
                : profile.name}
          </h1>
          {view === "settings" ? (
            <p>{isAndroid ? profile.name : scope}</p>
          ) : view === "devices" ? (
            <p>{t("common.separator.pair", { first: profile.name, second: t(`common.role.${accessLevel}`) })}</p>
          ) : (
            <div className="endpoint">
              <span>{t("home.details.serverAddress")}</span>
              <CopyValue
                value={`${profile.endpoint.host}:${profile.endpoint.wireguard_port}`}
                label={t("home.details.serverAddress")}
              />
            </div>
          )}
        </div>
      </header>}
      <Suspense fallback={<p role="status">{t("common.state.loading")}</p>}>
      {view === "home" && (
        <>
          {mobileConnection && <ConnectionOptions model={model} />}
          {mobileConnection && <PreferenceSaveBar preferences={model.preferences} local={model.localStatus} serverId={profile.id} />}
          {mobileDetails && <MobileConnectionDetails model={model} source={props.trafficUpdates} onReviewActivity={reviewActivity} />}
          {!mobileSubpage && <ConnectionHero model={model} view={view} onReviewComponentUpdate={() => setComponentUpdateOpen(true)} />}
          {isAndroid && !mobileSubpage && <ServerPicker servers={props.servers} selected={profile} local={model.localStatus} onSelect={props.onSelectServer} onAdd={props.onAddServer} onManage={() => props.onNavigate("servers")} />}
          {!mobileSubpage && (!isAndroid || model.connected) && <DeviceTraffic
            source={props.trafficUpdates}
            showDetails={false}
            onReviewUpdate={() => setComponentUpdateOpen(true)}
            local={model.localStatus}
            serverId={profile.id}
            address={profile.client_tunnel_address}
          />}
          {isAndroid && !mobileSubpage && <div className="mobile-choice-list home-links">
            <ListRow icon={<SlidersHorizontal size={22} />} title={t("app.home.connectionTitle")} subtitle={t("app.home.connectionSummary", { method: model.selectedTransport === "automatic" ? t("app.home.automatic") : formatTransport(model.selectedTransport) })} trailing={<CaretRight size={18} />} onClick={() => props.onNavigate("home", "connection")} />
            <ListRow icon={<Info size={22} />} title={t("app.home.detailsTitle")} subtitle={t("app.home.detailsSummary")} trailing={<CaretRight size={18} />} onClick={() => props.onNavigate("home", "details")} />
          </div>}
          {!isAndroid && <><ServerMetrics
            model={model}
            onReviewActivity={reviewActivity}
          />
          <DeviceTrafficDetails
            source={props.trafficUpdates}
            local={model.localStatus}
            serverId={profile.id}
            address={profile.client_tunnel_address}
          /></>}
        </>
      )}
      {view === "settings" && (
        <SettingsLayout category={category} onChange={onCategoryChange} mobile={isAndroid} detail={Boolean(props.detail)} onBack={props.onBack}>
          {category === "general" && (
            <GeneralSettings
              platform={isAndroid ? "android" : "desktop"}
              onCheckUpdates={props.onCheckUpdates}
              onReviewComponentUpdate={() => setComponentUpdateOpen(true)}
            />
          )}
          {category === "connection" && <ConnectionOptions model={model} />}
          {category === "network" && (
            <div className="settings-sections">
              <RoutingSettings model={model} />
              <section className="settings-card">
                <h2>{t("app.network.dnsTitle")}</h2>
                <p>
                  {model.serverStatus
                    ? t("common.separator.pair", { first: formatDnsPolicy(model.serverStatus.dns_upstream ?? { mode: "recursive" }), second: t(model.serverStatus.dns_healthy ? "home.server.dnsRunning" : "home.server.dnsDown") })
                    : t(!model.localKnown ? "app.network.dnsRefresh" : connected ? "app.network.dnsUnavailable" : "app.network.dnsNeedsConnection")}
                </p>
                {model.serverStatus?.private_dns_records?.length ? (
                  <dl className="health-checks">
                    {model.serverStatus.private_dns_records.map((record) => (
                      <div key={record.name}>
                        <dt>{record.name}</dt>
                        <dd className="mono">{record.address}</dd>
                      </div>
                    ))}
                  </dl>
                ) : null}
                {profile.role === "owner" && (
                  <div className="settings-action-row">
                    <p>{t("app.network.dnsChange")}</p>
                    <button
                      className="secondary-button"
                      onClick={() => {
                        model.setMaintenanceReview("dns");
                      }}
                    >
                      {t("app.network.dnsConfigure")}
                    </button>
                  </div>
                )}
              </section>
              <DnsBlocklistSettings profile={profile} connected={connected} canManage={model.canManageAccess} />
              {(
                <PortForwardSettings
                  onManageDevices={() => props.onNavigate("devices")}
                  profile={profile}
                  connected={connected}
                  accessLevel={accessLevel}
                  onAccessChanged={onAccessChanged}
                />
              )}
            </div>
          )}
          {category === "recovery" && (
            <MaintenanceTools
              model={model}
              category="recovery"
              onRestoreDevice={props.onRestoreDevice}
            />
          )}
          {category === "maintenance" && (
            <div className="settings-sections">
              <SystemHealth
                model={model}
              />
              <VpsAlertSettings profile={profile} connected={connected} />
              <MaintenanceTools
                model={model}
                category="maintenance"
                onRestoreDevice={props.onRestoreDevice}
              />
            </div>
          )}
          {(category === "connection" || category === "network") && <PreferenceSaveBar
            preferences={model.preferences}
            local={model.localStatus}
            serverId={profile.id}
          />}
        </SettingsLayout>
      )}
      {view === "devices" && (
          <AccessPanel
            profile={profile}
            connected={connected}
            accessLevel={accessLevel}
            onAccessChanged={onAccessChanged}
            onOpenHome={() => props.onNavigate("home")}
            onNetwork={() => {
              props.onOpenSettings("network");
            }}
          />
        )}
      {!isAndroid && <LocalComponentUpdate
        open={componentUpdateOpen}
        onOpenChange={setComponentUpdateOpen}
        onCheckUpdates={props.onCheckUpdates}
        disconnected={model.localKnown && model.localStatus.state === "disconnected" && model.localStatus.server_id === null && model.localStatus.kill_switch_state === "off"}
        onUpdated={async () => { model.clearConnectionError(); await model.onRefresh(); }}
      />}
      <WorkspaceDialogs onReviewAccess={() => props.onNavigate("devices")} model={model} onReturnHome={() => props.onNavigate("home")} />
      </Suspense>
    </div>
  );
}
