import {
  CaretDown,
  Cpu,
  HardDrives,
  Pulse,
  Devices,
} from "@phosphor-icons/react";
import {
  formatBytes,
  formatCount,
  formatCpuUsage,
  formatLatency,
  formatRate,
  formatUptime,
} from "../../format";
import { Metric } from "../../components/ui";
import { isAndroid } from "../../platform";
import type { ServerWorkspaceModel } from "./useServerWorkspace";

export function ServerMetrics({
  model,
  onReviewActivity,
}: {
  model: ServerWorkspaceModel;
  onReviewActivity: () => void;
}) {
  const { serverStatus: status, connected, freshness } = model;
  const live =
    connected &&
    Boolean(status) &&
    freshness.management === "ready" &&
    freshness.mode === "live";
  const freshnessLabel = !connected
    ? "Unavailable"
    : live
      ? "Live"
      : status && freshness.mode === "polling"
        ? "Automatic updates"
        : freshness.management === "refreshing"
          ? "Connecting…"
          : "Reconnecting…";
  const usage = (used?: number, total?: number) =>
    used !== undefined && total !== undefined && total > 0
      ? Math.min(100, (used / total) * 100)
      : undefined;
  const resource = (used?: number, total?: number) =>
    usage(used, total) === undefined
      ? "Unavailable"
      : `${Math.round(usage(used, total)!)}%`;
  const detail = (used?: number, total?: number) =>
    used === undefined || total === undefined
      ? "Measurement unavailable"
      : `${formatBytes(used)} of ${formatBytes(total)}`;
  return (
    <section className="server-metrics" aria-label="VPS overview">
      <div className="section-heading">
        <h2>VPS overview</h2>
        <span
          className={`section-meta metrics-stream-state${live ? " is-live" : ""}`}
          role="status"
        >
          {freshnessLabel}
        </span>
      </div>
      {!status ? (
        <div className="metrics-unavailable">
          <p>
            {!model.localKnown
              ? "Checking the local connection…"
              : connected
                ? "VPN connected · Server metrics unavailable"
                : "Connect to this server to view live VPS metrics."}
          </p>
          {model.localKnown && !connected && (
            <button
              className="secondary-button"
              disabled={model.busy || model.anotherConnected || model.active}
              onClick={() => void model.toggle()}
            >
              Connect to {model.profile.name}
            </button>
          )}
          {connected && (
            <small>
              Readings resume automatically when the management service is
              available.
            </small>
          )}
        </div>
      ) : (
        <>
          {freshness.mode === "polling" && (
            <p className="settings-note">
              Update the VPS software to enable live streaming. Readings update
              automatically in the meantime.
            </p>
          )}
          <div className="resource-grid">
            <Metric
              label="CPU"
              detail="CPU usage"
              value={
                status.cpu_usage_basis_points === undefined
                  ? "Unavailable"
                  : formatCpuUsage(status.cpu_usage_basis_points)
              }
              icon={<Cpu />}
              percent={
                status.cpu_usage_basis_points === undefined
                  ? undefined
                  : status.cpu_usage_basis_points / 100
              }
              kind={
                status.cpu_usage_basis_points === undefined
                  ? "state"
                  : "measurement"
              }
            />
            <Metric
              label="Memory"
              value={resource(
                status.memory_used_bytes,
                status.memory_total_bytes,
              )}
              detail={detail(
                status.memory_used_bytes,
                status.memory_total_bytes,
              )}
              icon={<HardDrives />}
              percent={usage(
                status.memory_used_bytes,
                status.memory_total_bytes,
              )}
              kind={
                usage(status.memory_used_bytes, status.memory_total_bytes) ===
                undefined
                  ? "state"
                  : "measurement"
              }
            />
            <Metric
              label="Storage"
              value={resource(status.disk_used_bytes, status.disk_total_bytes)}
              detail={`${detail(status.disk_used_bytes, status.disk_total_bytes)} · root`}
              icon={<HardDrives />}
              percent={usage(status.disk_used_bytes, status.disk_total_bytes)}
              kind={
                usage(status.disk_used_bytes, status.disk_total_bytes) ===
                undefined
                  ? "state"
                  : "measurement"
              }
            />
            <Metric
              label="VPS uptime"
              value={formatUptime(status.uptime_seconds)}
              detail="Since host boot"
              icon={<Pulse />}
              kind={
                Number.isFinite(status.uptime_seconds) ? "measurement" : "state"
              }
            />
            <Metric
              label="Devices"
              value={
                status.recently_active_peer_count === undefined
                  ? `${status.peer_count} authorized`
                  : `${status.recently_active_peer_count} / ${status.peer_count}`
              }
              detail={
                status.recently_active_peer_count === undefined
                  ? "Current activity unavailable"
                  : "Recently active / authorized"
              }
              icon={<Devices />}
              kind={
                status.recently_active_peer_count === undefined
                  ? "state"
                  : "measurement"
              }
            />
          </div>
          {status.recently_active_peer_count === undefined && (
            <div className="measurement-update">
              <p>
                {status.peer_activity_supported
                  ? "Device activity could not be read from WireGuard on the VPS."
                  : "This VPS does not provide device activity measurements. Review its software update."}
              </p>
              <button className="text-button" onClick={onReviewActivity}>
                {status.peer_activity_supported
                  ? "Review VPS health"
                  : "Review VPS update"}
              </button>
            </div>
          )}
          <details className="metrics-details">
            <summary>
              Server traffic & technical details{" "}
              <CaretDown className="disclosure-chevron" size={17} />
            </summary>
            <dl>
              <div>
                <dt>Server inbound</dt>
                <dd>{formatRate(status.rx_bytes_per_second)}</dd>
              </div>
              <div>
                <dt>Server outbound</dt>
                <dd>{formatRate(status.tx_bytes_per_second)}</dd>
              </div>
              <div>
                <dt>VPS received</dt>
                <dd>{formatBytes(status.rx_bytes)}</dd>
              </div>
              <div>
                <dt>VPS sent</dt>
                <dd>{formatBytes(status.tx_bytes)}</dd>
              </div>
              <div>
                <dt>VPS received packets</dt>
                <dd>{formatCount(status.rx_packets)}</dd>
              </div>
              <div>
                <dt>VPS sent packets</dt>
                <dd>{formatCount(status.tx_packets)}</dd>
              </div>
              {status.management_latency_ms !== undefined && (
                <div title="Time for an authenticated management status request; not tunnel latency.">
                  <dt>Management response</dt>
                  <dd>{formatLatency(status.management_latency_ms)}{isAndroid && <small>Authenticated management request; separate from tunnel latency.</small>}</dd>
                </div>
              )}
              <div>
                <dt>DNS service</dt>
                <dd>{status.dns_healthy ? "Running" : "Not responding"}</dd>
              </div>
            </dl>
            <p className="settings-note">
              VPS traffic combines all devices since the server VPN interface
              started. Live readings are sampled on the VPS once per second.
              Recently active means a handshake within three minutes; current
              presence is not guaranteed. Missing measurements stay unavailable.
            </p>
          </details>
        </>
      )}
    </section>
  );
}
