import { ArrowDown, ArrowUp, CaretDown, Timer } from "@phosphor-icons/react";
import { protectionEvidence } from "./protectionEvidence";
import { CopyValue } from "../../components/CopyValue";
import { Metric } from "../../components/ui";
import {
  formatBytes,
  formatRate,
  formatTunnelDuration,
  formatCount,
} from "../../format";
import type { LocalTunnelStatus } from "../../types";
import { useTunnelDuration } from "../../hooks/useTunnelDuration";
import { currentQualitySample } from "./TransportQuality";
import { MtuDetails } from "./MtuSettings";

import { useTrafficStore, type TrafficStore } from "../../hooks/trafficStore";
import { InfoHint } from "../../components/InfoHint";
import { formatNumber, t } from "../../i18n";
export function DeviceTraffic({
  local: fallback,
  source,
  serverId,
  address,

  showDetails = true,
  onReviewUpdate,
}: {
  local: LocalTunnelStatus;
  source?: TrafficStore<LocalTunnelStatus>;
  serverId: string;
  address?: string;

  showDetails?: boolean;
  onReviewUpdate?: () => void;
}) {
  const sample = useTrafficStore(source);
  const local = sample?.counter_epoch === fallback.counter_epoch && sample?.server_id === fallback.server_id && fallback.state === sample?.state ? sample : fallback;
  const connected = local.state === "connected" && local.server_id === serverId;
  const tunnelDuration = useTunnelDuration(local, serverId);
  const unsupported =
    connected && !local.traffic_metrics_supported && !local.counter_epoch;
  const sampling =
    connected &&
    Boolean(local.counter_epoch) &&
    local.tunnel_uptime_seconds !== undefined &&
    local.byte_counters_available !== false;
  const rate = (value: number | undefined) =>
    !connected
      ? t(local.state === "unknown" ? "common.state.unknown" : "common.state.notConnected")
      : value !== undefined
        ? formatRate(value)
        : t(sampling ? "home.traffic.measuring" : "format.unavailable");
  const available = (
    value: number | undefined,
    format: (n: number) => string,
  ) =>
    connected && value !== undefined
      ? format(value)
      : t(connected ? "format.unavailable" : local.state === "unknown" ? "common.state.unknown" : "common.state.notConnected");
  return (
    <section className="device-traffic" aria-label={t("home.traffic.label")}>
      <div className="section-heading">
        <h2>{t("common.noun.thisDevice")}</h2>
        <span className="section-meta">
          {t(connected ? "home.traffic.session" : local.state === "unknown" ? "home.traffic.countersUnavailable" : "home.traffic.notConnected")}
        </span>
      </div>
      <div className="device-traffic-grid">
        <Metric
          label={t("home.traffic.download")}
          value={rate(local.rx_bytes_per_second)}
          detail={
            connected
              ? local.byte_counters_available === false
                ? t("home.traffic.counterFailed")
                : t("home.traffic.received", { amount: formatBytes(local.rx_bytes) })
              : undefined
          }
          icon={<ArrowDown />}
          kind={
            connected && Number.isFinite(local.rx_bytes_per_second)
              ? "measurement"
              : "state"
          }
        />
        <Metric
          label={t("home.traffic.upload")}
          value={rate(local.tx_bytes_per_second)}
          detail={
            connected
              ? local.byte_counters_available === false
                ? t("home.traffic.counterFailed")
                : t("home.traffic.sent", { amount: formatBytes(local.tx_bytes) })
              : undefined
          }
          icon={<ArrowUp />}
          kind={
            connected && Number.isFinite(local.tx_bytes_per_second)
              ? "measurement"
              : "state"
          }
        />
        <Metric
          label={t("home.traffic.duration")}
          value={available(tunnelDuration, formatTunnelDuration)}
          detail={
            connected && tunnelDuration === undefined
              ? t(unsupported ? "home.traffic.needsUpdate" : "home.traffic.durationFailed")
              : undefined
          }
          icon={<Timer />}
          kind={
            connected && Number.isFinite(tunnelDuration)
              ? "measurement"
              : "state"
          }
        />
      </div>
      {unsupported && (
        <div className="measurement-update">
          <p>{t("home.traffic.updateNeeded")}</p>
          {onReviewUpdate && (
            <button className="text-button" onClick={onReviewUpdate}>
              {t("home.componentUpdate.review")}
            </button>
          )}
        </div>
      )}
      {showDetails && (
        <DeviceTrafficDetails
          local={local}
          serverId={serverId}
          address={address}

        />
      )}
    </section>
  );
}

export function DeviceTrafficDetails({
  local: fallback,
  source,
  serverId,
  address,

}: {
  local: LocalTunnelStatus;
  source?: TrafficStore<LocalTunnelStatus>;
  serverId: string;
  address?: string;

}) {
  const sample = useTrafficStore(source);
  const local = sample?.counter_epoch === fallback.counter_epoch && sample?.server_id === fallback.server_id && fallback.state === sample?.state ? sample : fallback;
  const connected = local.state === "connected" && local.server_id === serverId;
  const quality = connected ? currentQualitySample(local) : null;
  const available = (
    value: number | undefined,
    format: (n: number) => string,
  ) => (connected && value !== undefined ? format(value) : t("format.unavailable"));
  return (
    <details className="metrics-details">
      <summary>
        {t("home.device.summary")}{" "}
        <CaretDown className="disclosure-chevron" size={17} />
      </summary>
      <dl>
        <div>
          <dt>{t("home.device.receivedPackets")}</dt>
          <dd>{available(local.rx_packets, formatCount)}</dd>
        </div>
        <div>
          <dt>{t("home.device.sentPackets")}</dt>
          <dd>{available(local.tx_packets, formatCount)}</dd>
        </div>
        {address && (
          <div>
            <dt>{t("home.details.vpnAddress")}</dt>
            <dd>
              <CopyValue value={address} label={t("home.details.vpnAddress")} />
            </dd>
          </div>
        )}
        {connected && (
          <>
            <div>
              <dt>{t("home.device.latency")}<InfoHint text={t("home.device.latencyInfo")} /></dt>
              <dd>{quality ? t("format.latency", { value: formatNumber(quality.latency_micros / 1000, { minimumFractionDigits: 1, maximumFractionDigits: 1 }) }) : t("home.device.noMeasurement")}</dd>
            </div>
            {quality && <div><dt>{t("home.device.probes")}</dt><dd>{t("home.device.probesValue", { received: quality.probes_received, sent: quality.probes_sent, jitter: t("format.latency", { value: formatNumber(quality.jitter_micros / 1000, { minimumFractionDigits: 1, maximumFractionDigits: 1 }) }) })}</dd></div>}
            <div>
              <dt>{t("home.device.ipv6")}</dt>
              <dd>{protectionEvidence(local).ipv6}</dd>
            </div>
            <>
                <div>
                  <dt>{t("home.device.autoReconnect")}</dt>
                  <dd>{t(local.auto_reconnect_enabled ? "common.state.enabled" : "common.state.disabled")}</dd>
                </div>
                <div>
                  <dt>{t("home.device.fallback")}</dt>
                  <dd>{t(local.transport_fallback_enabled ? "common.state.enabled" : "common.state.disabled")}</dd>
                </div>
            </>
          </>
        )}
      </dl>
      {connected && local.mtu && <MtuDetails mtu={local.mtu} />}
      <p className="settings-note">{t("home.device.countersNote")}</p>
    </details>
  );
}
