import type { LocalTunnelStatus } from "../types";

export interface TrafficSample {
  local: LocalTunnelStatus;
  at: number;
}

/** One in-memory observation; discard it on failure, reconnect, reset or suspend. */
export function withTrafficRates(
  local: LocalTunnelStatus,
  at: number,
  previous: TrafficSample | null,
): LocalTunnelStatus {
  const sampledAt = local.counter_sampled_at_ms;
  const previousAt = previous?.local.counter_sampled_at_ms;
  const elapsed = previous ? ((sampledAt ?? at) - (previousAt ?? previous.at)) / 1000 : 0;
  const observation = { ...local, observed_at_ms: at, rx_bytes_per_second: undefined, tx_bytes_per_second: undefined };
  const sameSession =
    previous &&
    local.server_id === previous.local.server_id &&
    local.state === "connected" &&
    previous.local.state === "connected" &&
    local.byte_counters_available !== false &&
    previous.local.byte_counters_available !== false &&
    (sampledAt != null) === (previousAt != null) &&
    Boolean(local.counter_epoch) &&
    local.counter_epoch === previous.local.counter_epoch &&
    local.tunnel_uptime_seconds !== undefined &&
    previous.local.tunnel_uptime_seconds !== undefined &&
    local.tunnel_uptime_seconds >= previous.local.tunnel_uptime_seconds;
  // Commands and network events can republish the same native counter reading.
  if (sameSession && sampledAt != null && sampledAt === previousAt &&
      local.rx_bytes === previous.local.rx_bytes && local.tx_bytes === previous.local.tx_bytes)
    return { ...observation, rx_bytes_per_second: previous.local.rx_bytes_per_second, tx_bytes_per_second: previous.local.tx_bytes_per_second };
  if (
    !sameSession ||
    !Number.isFinite(elapsed) ||
    elapsed < 0.25 ||
    elapsed > 20
  )
    return observation;
  const rate = (before: number, after: number) =>
    Number.isSafeInteger(before) &&
    before >= 0 &&
    Number.isSafeInteger(after) &&
    after >= before
      ? (after - before) / elapsed
      : undefined;
  return {
    ...observation,
    rx_bytes_per_second: rate(previous.local.rx_bytes, local.rx_bytes),
    tx_bytes_per_second: rate(previous.local.tx_bytes, local.tx_bytes),
  };
}
