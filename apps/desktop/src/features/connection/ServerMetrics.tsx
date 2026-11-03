import {
  formatBytes,
  formatCount,
  formatCpuUsage,
  formatLatency,
  formatRate,
  formatUptime,
} from "../../format";
import { InfoHint } from "../../components/InfoHint";
import { formatNumber, t } from "../../i18n";
import type { ServerStatus } from "../../types";
import type { ServerWorkspaceModel } from "./useServerWorkspace";
import { SettingsDisclosure } from "../settings/SettingsParts";

export type ServerFreshness = "unavailable" | "live" | "polling" | "connecting" | "reconnecting";

export function serverFreshness(connected: boolean, status: ServerStatus | null, freshness: ServerWorkspaceModel["freshness"]): ServerFreshness {
  if (!connected) return "unavailable";
  if (status && freshness.management === "ready" && freshness.mode === "live") return "live";
  if (status && freshness.mode === "polling") return "polling";
  return freshness.management === "refreshing" ? "connecting" : "reconnecting";
}

const usage = (used?: number, total?: number) =>
  used !== undefined && total !== undefined && total > 0 ? Math.min(100, (used / total) * 100) : undefined;

/** The five server resource readings, shared by the desktop health row and the Android detail rows. */
export function serverMetrics(status: ServerStatus): { id: string; label: string; value: string; detail?: string; percent?: number; measured: boolean }[] {
  const resource = (used?: number, total?: number) => {
    const percent = usage(used, total);
    return {
      value: percent === undefined ? t("format.unavailable") : formatNumber(percent / 100, { style: "percent", maximumFractionDigits: 0 }),
      detail: used === undefined || total === undefined ? t("home.server.noMeasurement") : t("home.server.usedOf", { used: formatBytes(used), total: formatBytes(total) }),
      percent,
      measured: percent !== undefined,
    };
  };
  const activity = status.recently_active_peer_count;
  return [
    { id: "cpu", label: t("home.server.cpu"), value: status.cpu_usage_basis_points === undefined ? t("format.unavailable") : formatCpuUsage(status.cpu_usage_basis_points),
      detail: t(status.cpu_usage_basis_points === undefined ? "home.server.noMeasurement" : "home.server.cpuDetail"),
      percent: status.cpu_usage_basis_points === undefined ? undefined : status.cpu_usage_basis_points / 100, measured: status.cpu_usage_basis_points !== undefined },
    { id: "memory", label: t("home.server.memory"), ...resource(status.memory_used_bytes, status.memory_total_bytes) },
    { id: "storage", label: t("home.server.storage"), ...resource(status.disk_used_bytes, status.disk_total_bytes) },
    { id: "uptime", label: t("home.server.uptime"), value: formatUptime(status.uptime_seconds), measured: Number.isFinite(status.uptime_seconds) },
    { id: "devices", label: t("home.server.devices"),
      value: activity === undefined ? t("home.server.devicesAuthorized", { count: status.peer_count }) : t("home.server.devicesActive", { active: activity, total: status.peer_count }),
      detail: activity === undefined ? t("home.server.activityUnavailable") : undefined, measured: activity !== undefined },
  ];
}

export function ServerMetrics({
  model,
  onReviewActivity,
  onReviewUpdate,
}: {
  model: ServerWorkspaceModel;
  onReviewActivity: () => void;
  /** Owners only: opens the VPS update review. */
  onReviewUpdate?: () => void;
}) {
  const { serverStatus: status, connected, freshness } = model;
  const state = serverFreshness(connected, status, freshness);
  return (
    <section className="server-metrics" aria-label={t("home.server.title")}>
      <div className="section-heading">
        <h2>{t("home.server.title")}</h2>
        {state !== "unavailable" && <span
          className={`section-meta metrics-stream-state${state === "live" ? " is-live" : ""}`}
          role="status"
        >
          {t(`home.server.freshness.${state}`)}
        </span>}
      </div>
      {!status ? (
        <div className="metrics-unavailable">
          <p>
            {t(!model.localKnown ? "common.state.checking" : connected ? "home.server.unavailable" : "home.server.connectToSee")}
          </p>
        </div>
      ) : (
        <>
          {freshness.mode === "polling" && (
            <div className="measurement-update">
              <p>{t(onReviewUpdate ? "home.server.pollingNote" : "home.server.pollingNoteMember")}</p>
              {onReviewUpdate && <button className="text-button" onClick={onReviewUpdate}>{t("home.server.reviewUpdate")}</button>}
            </div>
          )}
          {/* One compact row under the status card; the amounts behind each reading are in Server details. */}
          <dl className="server-health">
            {serverMetrics(status).map(metric => (
              <div key={metric.id} data-measured={metric.measured}>
                <dt>{metric.label}</dt>
                <dd>
                  {metric.value}
                  {/* Same thresholds as the usage tiles: amber from 85%, red from 95%. */}
                  {metric.percent !== undefined && Number.isFinite(metric.percent) && <meter min={0} max={100} low={85} high={95} optimum={0}
                    value={Math.max(0, Math.min(100, metric.percent))} aria-label={t("app.metric.usage", { label: metric.label })} />}
                </dd>
              </div>
            ))}
          </dl>
          {status.recently_active_peer_count === undefined && (
            <div className="measurement-update">
              <p>{t(status.peer_activity_supported ? "home.server.activityUnreadable" : "home.server.activityUnsupported")}</p>
              <button className="text-button" onClick={onReviewActivity}>
                {t(status.peer_activity_supported ? "home.server.reviewHealth" : "home.server.reviewUpdate")}
              </button>
            </div>
          )}
          <SettingsDisclosure className="metrics-details" summary={t("home.server.detailsSummary")}>
            <dl>
              {serverMetrics(status).filter(metric => metric.id === "memory" || metric.id === "storage").map(metric => (
                <div key={metric.id}>
                  <dt>{metric.label}</dt>
                  <dd>{metric.detail}</dd>
                </div>
              ))}
              <div>
                <dt>{t("home.server.inbound")}</dt>
                <dd>{formatRate(status.rx_bytes_per_second)}</dd>
              </div>
              <div>
                <dt>{t("home.server.outbound")}</dt>
                <dd>{formatRate(status.tx_bytes_per_second)}</dd>
              </div>
              <div>
                <dt>{t("home.server.received")}</dt>
                <dd>{formatBytes(status.rx_bytes)}</dd>
              </div>
              <div>
                <dt>{t("home.server.sent")}</dt>
                <dd>{formatBytes(status.tx_bytes)}</dd>
              </div>
              <div>
                <dt>{t("home.server.receivedPackets")}</dt>
                <dd>{formatCount(status.rx_packets)}</dd>
              </div>
              <div>
                <dt>{t("home.server.sentPackets")}</dt>
                <dd>{formatCount(status.tx_packets)}</dd>
              </div>
              {status.management_latency_ms !== undefined && (
                <div>
                  <dt>{t("home.details.serverResponse")}<InfoHint text={t("home.details.serverResponseInfo")} /></dt>
                  <dd>{formatLatency(status.management_latency_ms)}</dd>
                </div>
              )}
              <div>
                <dt>{t("home.server.dns")}</dt>
                <dd>{t(status.dns_healthy ? "home.server.dnsRunning" : "home.server.dnsDown")}</dd>
              </div>
            </dl>
            <p className="settings-note">{t("home.server.totalsInfo")}</p>
          </SettingsDisclosure>
        </>
      )}
    </section>
  );
}
