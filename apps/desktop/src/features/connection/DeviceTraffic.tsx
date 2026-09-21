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
      ? local.state === "unknown"
        ? "Unknown"
        : "Not connected"
      : value !== undefined
        ? formatRate(value)
        : sampling
          ? "Sampling…"
          : "Unavailable";
  const available = (
    value: number | undefined,
    format: (n: number) => string,
  ) =>
    connected && value !== undefined
      ? format(value)
      : connected
        ? "Unavailable"
        : local.state === "unknown"
          ? "Unknown"
          : "Not connected";
  return (
    <section className="device-traffic" aria-label="This device traffic">
      <div className="section-heading">
        <h2>This device</h2>
        <span className="section-meta">
          {connected
            ? "Current tunnel · resets on reconnect"
            : local.state === "unknown"
              ? "Counters unavailable"
              : "No active tunnel to this server"}
        </span>
      </div>
      <div className="device-traffic-grid">
        <Metric
          label="Download"
          value={rate(local.rx_bytes_per_second)}
          detail={
            connected
              ? local.byte_counters_available === false
                ? "Counter reading failed"
                : `${formatBytes(local.rx_bytes)} received`
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
          label="Upload"
          value={rate(local.tx_bytes_per_second)}
          detail={
            connected
              ? local.byte_counters_available === false
                ? "Counter reading failed"
                : `${formatBytes(local.tx_bytes)} sent`
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
          label="Tunnel duration"
          value={available(tunnelDuration, formatTunnelDuration)}
          detail={
            connected && tunnelDuration === undefined
              ? unsupported
                ? "Requires an updated VPN component"
                : "Session timing could not be read"
              : connected
                ? "Current connection duration"
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
          <p>Live rates and duration require an updated local VPN component.</p>
          {onReviewUpdate && (
            <button className="text-button" onClick={onReviewUpdate}>
              Review update
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
  ) => (connected && value !== undefined ? format(value) : "Unavailable");
  return (
    <details className="metrics-details">
      <summary>
        Device counters & connection details{" "}
        <CaretDown className="disclosure-chevron" size={17} />
      </summary>
      <dl>
        <div>
          <dt>Received packets</dt>
          <dd>{available(local.rx_packets, formatCount)}</dd>
        </div>
        <div>
          <dt>Sent packets</dt>
          <dd>{available(local.tx_packets, formatCount)}</dd>
        </div>
        {address && (
          <div>
            <dt>Assigned VPN address</dt>
            <dd>
              <CopyValue value={address} label="device VPN address" />
            </dd>
          </div>
        )}
        {connected && (
          <>
            <div>
              <dt>Private-tunnel latency</dt>
              <dd>{quality ? `${(quality.latency_micros / 1000).toFixed(1)} ms` : "No current measurement"}</dd>
            </div>
            {quality && <div><dt>Probe delivery</dt><dd>{quality.probes_received} / {quality.probes_sent} replies · {(quality.jitter_micros / 1000).toFixed(1)} ms jitter</dd></div>}
            <div>
              <dt>IPv6 handling</dt>
              <dd>{protectionEvidence(local).ipv6}</dd>
            </div>
            <>
                <div>
                  <dt>Automatic reconnect</dt>
                  <dd>
                    {local.auto_reconnect_enabled
                      ? "Configured"
                      : "Disabled for this connection"}
                  </dd>
                </div>
                <div>
                  <dt>Transport fallback</dt>
                  <dd>
                    {local.transport_fallback_enabled
                      ? "Configured"
                      : "Disabled for this connection"}
                  </dd>
                </div>
            </>
          </>
        )}
      </dl>
      {connected && local.mtu && <MtuDetails mtu={local.mtu} />}
      {connected && <p className="settings-note">Latency is the average ICMP round trip through this tunnel to the private VPS address. It measures the current VPN path, not internet speed or a management request.</p>}
      <p className="settings-note">
        Packets and bytes belong to this device's current tunnel interface.
        Rates use the latest two local readings; no activity history is saved.
      </p>
    </details>
  );
}
