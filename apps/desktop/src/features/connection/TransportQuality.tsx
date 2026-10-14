import type { LocalTunnelStatus } from "../../types";
import { formatNumber, t } from "../../i18n";

const milliseconds = (micros: number) =>
  t("format.latency", { value: formatNumber(micros / 1000, { minimumFractionDigits: 1, maximumFractionDigits: 1 }) });

export function TransportQuality({ status }: { status: LocalTunnelStatus }) {
  const quality = status.transport_quality;
  if (!quality) return null;
  const sample = currentQualitySample(status);
  const reason = quality.last_switch_reason ? t(`connection.quality.reason.${quality.last_switch_reason}`) : null;
  return <div className="settings-note" aria-label={t("connection.quality.label")}>
    {sample && <p>{t("connection.quality.sample", {
      latency: milliseconds(sample.latency_micros),
      jitter: milliseconds(sample.jitter_micros),
      loss: formatNumber(1 - sample.probes_received / sample.probes_sent, { style: "percent", maximumFractionDigits: 0 }),
    })}</p>}
    {reason && <p>{reason}</p>}
    <p>{t(`connection.quality.selection.${quality.selection}`)}</p>
  </div>;
}

export function currentQualitySample(status: LocalTunnelStatus) {
  const sample = status.transport_quality?.sample;
  if (status.state !== "connected" || status.supervisor_status_known === false || !sample || sample.transport !== status.transport ||
      sample.probes_sent !== 8 || !Number.isInteger(sample.probes_received) || sample.probes_received < 1 || sample.probes_received > sample.probes_sent ||
      !Number.isFinite(sample.latency_micros) || sample.latency_micros < 0 || sample.latency_micros > 3_000_000 ||
      !Number.isFinite(sample.jitter_micros) || sample.jitter_micros < 0 || sample.jitter_micros > 3_000_000) return null;
  return sample;
}
