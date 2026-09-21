import { describe, expect, it } from "vitest";
import { emptyLocalStatus } from "./useDesktopStatus";
import { withTrafficRates } from "./trafficSample";
const sample = {
  ...emptyLocalStatus,
  state: "connected" as const,
  server_id: "a",
  rx_bytes: 1000,
  tx_bytes: 500,
  tunnel_uptime_seconds: 10,
  counter_epoch: "first",
};
describe("device traffic measurements", () => {
  it("uses device byte deltas and elapsed time, independently of VPS counters", () => {
    const next = withTrafficRates(
      { ...sample, rx_bytes: 3000, tx_bytes: 1500, tunnel_uptime_seconds: 14 },
      5000,
      { local: sample, at: 1000 },
    );
    expect(next.rx_bytes_per_second).toBe(500);
    expect(next.tx_bytes_per_second).toBe(250);
  });
  it("does not bridge a reconnect, server switch, reset, suspend or missing measurement", () => {
    for (const next of [
      { ...sample, counter_epoch: "second" },
      { ...sample, server_id: "b" },
      { ...sample, state: "disconnected" as const },
      { ...sample, counter_epoch: undefined },
      { ...sample, counter_epoch: "" },
      { ...sample, byte_counters_available: false, rx_bytes: 0 },
      { ...sample, rx_bytes: Number.NaN },
      { ...sample, rx_bytes: Number.MAX_SAFE_INTEGER + 10 },
    ]) {
      expect(
        withTrafficRates(next, 5000, { local: sample, at: 1000 })
          .rx_bytes_per_second,
      ).toBeUndefined();
    }
    expect(
      withTrafficRates({ ...sample, rx_bytes: 2 }, 5000, {
        local: sample,
        at: 1000,
      }).rx_bytes_per_second,
    ).toBeUndefined();
    expect(
      withTrafficRates(sample, 30000, { local: sample, at: 1000 })
        .rx_bytes_per_second,
    ).toBeUndefined();
    expect(
      withTrafficRates(sample, 5000, null).rx_bytes_per_second,
    ).toBeUndefined();
  });
});
