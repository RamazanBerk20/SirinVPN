const GeneralSettings = lazy(() => import("../settings/GeneralSettings").then(m => ({ default: m.GeneralSettings })));
import {
  SettingsLayout,
  type SettingsCategory,
} from "../settings/SettingsLayout";
import { ConnectionHero, ConnectionDetails } from "./ConnectionHero";
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
const PortForwardSettings = lazy(() => import("../devices/PortForwardSettings").then(m => ({ default: m.PortForwardSettings })));
import { formatDnsPolicy } from "../../format";
import { useServerWorkspace } from "./useServerWorkspace";
import { isAndroid } from "../../platform";
import { Brand } from "../../components/Brand";
import { ArrowLeft, CaretRight, Database, SlidersHorizontal, Info } from "@phosphor-icons/react";
import { formatTransport } from "../../format";

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
  },
) {
  const model = useServerWorkspace(props);
  const [componentUpdateOpen, setComponentUpdateOpen] = useState(false);
  const handledTrayRequest = useRef<number | null>(null);
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
  const scope =
    category === "general"
      ? "App-wide preferences · this device"
      : category === "connection"
        ? `${profile.name} · this device's next connection`
        : category === "network"
          ? `${profile.name} · device routing and VPS networking`
          : category === "recovery"
            ? `${profile.name} · keys & recovery`
            : `${profile.name} · VPS operations`;
  return (
    <div
      className={`server-workspace view-${view}`}
      hidden={view === "servers"}
    >
      {isAndroid && view === "home" && (mobileDetails ?
        <header className="mobile-page-header"><button className="icon-button" aria-label="Back" onClick={props.onBack}><ArrowLeft size={24} /></button><h1>Connection details</h1></header> :
        <header className="mobile-home-header"><Brand compact /><span className="mobile-device-label">This phone</span></header>)}
      {(!isAndroid || view === "devices" || view === "settings" && !props.detail) && <header className="workspace-header">
        <div>
          <h1>
            {view === "settings"
              ? "Settings"
              : view === "devices"
                ? "Devices"
                : profile.name}
          </h1>
          {view === "settings" ? (
            <p>{isAndroid ? `Manage ${profile.name} and this phone` : scope}</p>
          ) : view === "devices" ? (
            <p>
              {profile.name} ·{" "}
              {accessLevel === "owner"
                ? "Owner"
                : accessLevel === "admin"
                  ? "Admin"
                  : "Member"}{" "}
              access
            </p>
          ) : (
            <div className="endpoint">
              <span>VPN endpoint</span>
              <CopyValue
                value={`${profile.endpoint.host}:${profile.endpoint.wireguard_port}`}
                label="VPN endpoint"
              />
            </div>
          )}
        </div>
      </header>}
      <Suspense fallback={<p role="status">Loading…</p>}>
      {view === "home" && (
        <>
          {!mobileDetails && <ConnectionHero model={model} view={view} onReviewComponentUpdate={() => setComponentUpdateOpen(true)} />}
          {isAndroid && !mobileDetails && <button className="mobile-list-row mobile-server-picker" onClick={() => props.onNavigate("servers")} aria-label={`Change server, ${profile.name}`}><span className="mobile-row-icon"><Database size={24} /></span><span><small>Your server</small><strong>{profile.name}</strong></span><CaretRight size={20} /></button>}
          {mobileDetails && <><p className="mobile-scope">{profile.name}</p><ConnectionDetails model={model} /><div className="endpoint"><span>VPN endpoint</span><CopyValue value={`${profile.endpoint.host}:${profile.endpoint.wireguard_port}`} label="VPN endpoint" /></div></>}
          <DeviceTraffic
            source={props.trafficUpdates}
            showDetails={false}
            onReviewUpdate={() => setComponentUpdateOpen(true)}
            local={model.localStatus}
            serverId={profile.id}
            address={profile.client_tunnel_address}
          />
          {isAndroid && !mobileDetails && <div className="mobile-home-links">
            <button className="mobile-list-row" onClick={() => props.onOpenSettings("connection")}><SlidersHorizontal size={23} /><span><strong>Connection mode</strong><small>{model.selectedTransport === "automatic" ? "Automatic" : formatTransport(model.selectedTransport)}</small></span><CaretRight size={18} /></button>
            <button className="mobile-list-row" onClick={() => props.onNavigate("home", "details")}><Info size={23} /><span><strong>Connection details</strong><small>Protection, traffic & server status</small></span><CaretRight size={18} /></button>
          </div>}
          {(!isAndroid || mobileDetails) && <><ServerMetrics
            model={model}
            onReviewActivity={() => {
              props.onOpenSettings("maintenance");
              if (
                model.serverStatus &&
                !model.serverStatus.peer_activity_supported &&
                profile.role === "owner"
              ) {
                model.setMaintenanceReview("update");
              }
            }}
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
                <h2>DNS · VPS configuration</h2>
                <p>
                  {model.serverStatus
                    ? `${formatDnsPolicy(model.serverStatus.dns_upstream ?? { mode: "recursive" })} · ${model.serverStatus.dns_healthy ? "Service running" : "Service not responding"}`
                    : !model.localKnown
                      ? "Refresh local status before inspecting this server's DNS configuration."
                      : connected
                        ? "VPS DNS configuration is unavailable. The local VPN remains connected."
                        : "Live DNS status requires a VPN connection."}
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
                    <p>
                      Configuration changes use verified SSH access and affect
                      all devices. Review the required disconnect on this
                      {isAndroid ? " phone." : " computer."}
                    </p>
                    <button
                      className="secondary-button"
                      onClick={() => {
                        model.setMaintenanceReview("dns");
                      }}
                    >
                      Configure VPS DNS
                    </button>
                  </div>
                )}
              </section>
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
              <MaintenanceTools
                model={model}
                category="maintenance"
                onRestoreDevice={props.onRestoreDevice}
              />
            </div>
          )}
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
      <WorkspaceDialogs onReviewAccess={() => props.onNavigate("devices")} model={model} view={view} onReturnHome={() => props.onNavigate("home")} />
      </Suspense>
    </div>
  );
}
