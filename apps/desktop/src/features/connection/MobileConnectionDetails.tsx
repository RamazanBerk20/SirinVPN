import type { ReactNode } from "react";
import { CopyValue } from "../../components/CopyValue";
import { InfoHint } from "../../components/InfoHint";
import { formatBytes, formatCount, formatLatency, formatRate, formatTransport } from "../../format";
import { useTrafficStore, type TrafficStore } from "../../hooks/trafficStore";
import { formatNumber, t } from "../../i18n";
import type { LocalTunnelStatus } from "../../types";
import { describeConnection } from "./connectionState";
import { MtuDetails } from "./MtuSettings";
import { protectionEvidence } from "./protectionEvidence";
import { serverFreshness, serverMetrics } from "./ServerMetrics";
import { currentQualitySample } from "./TransportQuality";
import type { ServerWorkspaceModel } from "./useServerWorkspace";

function Group({ title, meta, children }: { title: string; meta?: ReactNode; children: ReactNode }) {
  return <section className="detail-group">
    <div className="detail-group-heading"><h2>{title}</h2>{meta}</div>
    <dl className="detail-list">{children}</dl>
  </section>;
}

function Row({ label, value, note, info, stacked }: { label: string; value: ReactNode; note?: string | null; info?: string; stacked?: boolean }) {
  return <div className={stacked ? "stacked" : undefined}>
    <dt>{label}{info && <InfoHint text={info} />}</dt>
    <dd>{value}{note && <small>{note}</small>}</dd>
  </div>;
}

/** Android's Connection details page: grouped label/value rows instead of desktop metric tiles. */
export function MobileConnectionDetails({ model, source, onReviewActivity }: {
  model: ServerWorkspaceModel;
  source?: TrafficStore<LocalTunnelStatus>;
  onReviewActivity: () => void;
}) {
  const { profile, serverStatus: server, freshness } = model;
  const sample = useTrafficStore(source);
  const fallback = model.localStatus;
  const local = sample?.counter_epoch === fallback.counter_epoch && sample?.server_id === fallback.server_id && sample?.state === fallback.state ? sample : fallback;
  const state = describeConnection(local, profile.id, server, model.preferences.saved?.policy);
  const connected = state.connected;
  const quality = connected ? currentQualitySample(local) : null;
  const freshnessState = serverFreshness(connected, server, freshness);
  return <div className="mobile-details">
    <Group title={t("home.details.connection")}>
      <Row label={t("home.details.status")} value={state.status} />
      <Row label={t("home.details.method")} value={state.active ? formatTransport(local.transport) : state.known ? t("home.routing.inactive") : t("common.state.unknown")} />
      <Row label={t("home.details.routing")} value={state.routing} />
      <Row label={t("home.details.killSwitch")} value={state.protection} note={state.protectionDetail} />
      {state.applicationIsolation && <Row label={t("home.details.appIsolation")} value={state.applicationIsolation} />}
      {connected && <Row label={t("home.details.reachability")} value={state.health.reachability} note={state.health.detail} />}
      {connected && server?.management_latency_ms !== undefined && <Row label={t("home.details.serverResponse")} value={formatLatency(server.management_latency_ms)} info={t("home.details.serverResponseInfo")} />}
    </Group>
    <Group title={t("home.details.addresses")}>
      <Row stacked label={t("home.details.serverAddress")} value={<CopyValue value={`${profile.endpoint.host}:${profile.endpoint.wireguard_port}`} label={t("home.details.serverAddress")} />} />
      <Row stacked label={t("home.details.vpnAddress")} value={<CopyValue value={profile.client_tunnel_address} label={t("home.details.vpnAddress")} />} />
    </Group>
    <Group title={t("home.details.thisDevice")}>
      {connected ? <>
        <Row label={t("home.device.receivedPackets")} value={formatCount(local.rx_packets)} />
        <Row label={t("home.device.sentPackets")} value={formatCount(local.tx_packets)} />
        <Row label={t("home.device.latency")} value={quality ? t("format.latency", { value: formatNumber(quality.latency_micros / 1000, { maximumFractionDigits: 1 }) }) : t("home.device.noMeasurement")} info={t("home.device.latencyInfo")} />
        {quality && <Row label={t("home.device.probes")} value={t("home.device.probesValue", { received: quality.probes_received, sent: quality.probes_sent, jitter: t("format.latency", { value: formatNumber(quality.jitter_micros / 1000, { maximumFractionDigits: 1 }) }) })} />}
        <Row label={t("home.device.ipv6")} value={protectionEvidence(local).ipv6} />
        <Row label={t("home.device.autoReconnect")} value={t(local.auto_reconnect_enabled ? "common.state.enabled" : "common.state.disabled")} />
        <Row label={t("home.device.fallback")} value={t(local.transport_fallback_enabled ? "common.state.enabled" : "common.state.disabled")} />
      </> : <Row label={t("home.details.status")} value={t("common.state.notConnected")} />}
    </Group>
    {connected && local.mtu && <section className="detail-group"><div className="detail-group-heading"><h2>{t("home.details.mtu")}</h2></div><MtuDetails mtu={local.mtu} /></section>}
    <Group title={t("home.server.title")} meta={<span className={`section-meta metrics-stream-state${freshnessState === "live" ? " is-live" : ""}`} role="status">{t(`home.server.freshness.${freshnessState}`)}</span>}>
      {server ? <>
        {serverMetrics(server).map(metric => <Row key={metric.id} label={metric.label} value={metric.value} note={metric.detail} />)}
        <Row label={t("home.server.dns")} value={t(server.dns_healthy ? "home.server.dnsRunning" : "home.server.dnsDown")} />
        <Row label={t("home.server.inbound")} value={formatRate(server.rx_bytes_per_second)} />
        <Row label={t("home.server.outbound")} value={formatRate(server.tx_bytes_per_second)} />
        <Row label={t("home.server.received")} value={formatBytes(server.rx_bytes)} info={t("home.server.totalsInfo")} />
        <Row label={t("home.server.sent")} value={formatBytes(server.tx_bytes)} />
      </> : <Row label={t("home.details.status")} value={t(!model.localKnown ? "common.state.checking" : connected ? "home.server.unavailable" : "home.server.connectToSee")} />}
    </Group>
    {server && server.recently_active_peer_count === undefined && <div className="measurement-update">
      <p>{t(server.peer_activity_supported ? "home.server.activityUnreadable" : "home.server.activityUnsupported")}</p>
      <button className="text-button" onClick={onReviewActivity}>{t(server.peer_activity_supported ? "home.server.reviewHealth" : "home.server.reviewUpdate")}</button>
    </div>}
  </div>;
}
