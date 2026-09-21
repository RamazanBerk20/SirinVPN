import { useEffect, useState } from "react";
import type { LocalTunnelStatus } from "../types";

// Local status normally arrives every four seconds. Do not keep an unverified
// connection clock running through a stalled helper, suspended app or lost IPC.
const MAX_SAMPLE_AGE_MS = 15_000;

export function useTunnelDuration(local: LocalTunnelStatus, serverId: string) {
  const [now, setNow] = useState(() => performance.now());
  const seconds = local.tunnel_uptime_seconds;
  const observed = local.observed_at_ms;
  const connected = local.state === "connected" && local.server_id === serverId;
  const measured =
    connected &&
    seconds !== undefined &&
    Number.isFinite(seconds) &&
    seconds >= 0;
  const ticking =
    measured &&
    Boolean(local.counter_epoch) &&
    observed !== undefined &&
    Number.isFinite(observed);

  useEffect(() => {
    if (!ticking) return;
    let timer: number | undefined;
    const resume = () => {
      window.clearInterval(timer);
      if (document.hidden) return;
      setNow(performance.now());
      timer = window.setInterval(() => setNow(performance.now()), 1000);
    };
    resume();
    document.addEventListener("visibilitychange", resume);
    return () => {
      window.clearInterval(timer);
      document.removeEventListener("visibilitychange", resume);
    };
    // New observations correct the anchor below without restarting the clock.
  }, [ticking, local.counter_epoch, serverId]);

  if (!measured) return undefined;
  if (!ticking) return seconds;
  const age = Math.max(now, performance.now()) - observed;
  if (age < 0 || age > MAX_SAMPLE_AGE_MS) return undefined;
  return Math.floor(seconds + age / 1000);
}
