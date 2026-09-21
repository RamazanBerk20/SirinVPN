import type { LocalTunnelStatus } from "../../types";

const selectionText = {
  pending: "Waiting for a tunnel quality measurement.",
  observing: "Current private tunnel measurement.",
  waiting_for_idle: "Automatic mode will compare alternatives when traffic is quiet.",
  comparing: "Measuring alternative transports.",
  selected: "Using the best measured transport from the current comparison.",
  icmp_unavailable: "The VPS did not answer the quality probes. Latency and loss are unavailable.",
  protection_required: "Enable the kill switch to allow protected transport comparisons.",
};
export function TransportQuality({ status }: { status: LocalTunnelStatus }) {
  const quality = status.transport_quality;
  if (!quality) return null;
  const sample = currentQualitySample(status);
  const reason = quality.last_switch_reason === "confirmed_failure" ? "Transport changed after connectivity checks failed."
    : quality.last_switch_reason === "quality_improvement" ? "Switched to a consistently better measured transport."
    : quality.last_switch_reason === "rollback" ? "Kept the previous transport because the alternative did not connect." : null;
  return <div className="settings-note" aria-label="Current transport quality">
    {sample && <p>{(sample.latency_micros / 1000).toFixed(1)} ms latency · {(sample.jitter_micros / 1000).toFixed(1)} ms jitter · {Math.round(100 * (1 - sample.probes_received / sample.probes_sent))}% probe loss ({sample.probes_received}/{sample.probes_sent} replies)</p>}
    {reason && <p>{reason}</p>}
    <p>{selectionText[quality.selection]} Measurements cover the private VPN path; they do not measure download speed.</p>
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
