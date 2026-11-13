import { useCallback, useEffect, useMemo, useRef, useState, type Dispatch, type SetStateAction } from "react";
import { api } from "../api";
import { withTrafficRates, type TrafficSample } from "./trafficSample";
import type {
  ClientPlatform,
  LocalTunnelStatus,
  ServerProfile,
} from "../types";

import { TrafficStore } from "./trafficStore";
import { feedFreshness, initialStatusFeed, statusFeedReducer, type StatusFeedAction } from "./statusFeed";

/** How long a requested local reading may take before the UI stops showing "Checking". */
const LOCAL_READ_TIMEOUT_MS = 10_000;

export const emptyLocalStatus: LocalTunnelStatus = {
  state: "disconnected",
  interface_name: "sirinvpn0",
  server_id: null,
  rx_bytes: 0,
  tx_bytes: 0,
  ipv6_blocked: false,
  ipv6_tunneled: false,
  kill_switch_enabled: false,
  auto_reconnect_enabled: false,
  transport_fallback_enabled: false,
  routing_mode: "full_tunnel",
  allow_lan: false,
};

export interface StatusFreshness {
  refreshing: boolean;
  updatedAt: number | null;
  management: "idle" | "refreshing" | "ready" | "reconnecting" | "unavailable";
  mode?: "live" | "polling";
}

/** Local tunnel checks and the VPS stream have independent lifetimes. */
export const favoritesFirst = (profiles: ServerProfile[]) =>
  [...profiles].sort((a, b) => Number(Boolean(b.favorite)) - Number(Boolean(a.favorite)));

export function useDesktopStatus(
  platform: ClientPlatform | null,
  setServers: Dispatch<SetStateAction<ServerProfile[]>>,
) {
  const [feed, setFeed] = useState(() => initialStatusFeed({ ...emptyLocalStatus, state: "unknown" }));
  // Mirrors `feed` synchronously, so a stream callback can drop an event the moment its subscription is replaced.
  const feedRef = useRef(feed);
  const send = useCallback((action: StatusFeedAction) => {
    const next = statusFeedReducer(feedRef.current, action);
    if (next === feedRef.current) return;
    feedRef.current = next;
    setFeed(next);
  }, []);
  const traffic = useRef<TrafficSample | null>(null);
  const trafficUpdates = useMemo(() => new TrafficStore<LocalTunnelStatus>(), []);
  // Numbers local reads; a read answered after a newer one started (or after hiding) is dropped.
  const generation = useRef(0);
  const endpointCheckpoint = useRef("");

  const receiveLocal = useCallback((request: number, raw: LocalTunnelStatus | null) => {
    if (request !== generation.current) return;
    if (!raw) {
      traffic.current = null;
      send({ type: "localEvent", event: { kind: "failed" } });
      return;
    }
    if (raw.endpoint_checkpoint) {
      const key = `${raw.endpoint_checkpoint.claims.server_id}:${raw.endpoint_checkpoint.claims.generation}`;
      if (endpointCheckpoint.current !== key) {
        endpointCheckpoint.current = key;
        // Profile metadata must not delay publishing an already-read tunnel state.
        void api.listServers().then(profiles => { if (endpointCheckpoint.current === key) setServers(favoritesFirst(profiles)); }).catch(() => { endpointCheckpoint.current = ""; });
      }
    }
    const at = performance.now();
    const local = withTrafficRates(raw, at, traffic.current);
    traffic.current = { local, at };
    trafficUpdates.publish(local);
    send({ type: "localEvent", event: { kind: "reading", local } });
  }, [send, setServers, trafficUpdates]);

  const refreshStatus = useCallback(async (supplied?: LocalTunnelStatus) => {
    const request = ++generation.current;
    if (supplied) { receiveLocal(request, supplied); return; }
    send({ type: "refresh" });
    // A read that never answers must not leave "Checking" up forever.
    const timer = window.setTimeout(() => { if (request === generation.current) send({ type: "timer" }); }, LOCAL_READ_TIMEOUT_MS);
    try {
      receiveLocal(request, await api.localStatus());
    } catch {
      receiveLocal(request, null);
    } finally {
      window.clearTimeout(timer);
    }
  }, [receiveLocal, send]);

  const streamServer = feed.serverFeed.state === "off" ? null : feed.serverFeed.serverId;
  const streamEpoch = feed.serverFeed.state === "off" ? null : feed.serverFeed.epoch;
  useEffect(() => {
    if ((platform !== "desktop" && platform !== "android") || !streamServer || streamEpoch === null) return;
    let open = true;
    // Closed by cleanup, and already stale the moment a reading replaces this subscription.
    const current = () => {
      const server = feedRef.current.serverFeed;
      return open && server.state !== "off" && server.epoch === streamEpoch;
    };
    const stop = api.watchServerStatus(streamServer, (event) => {
      if (!current()) return;
      if (event.kind === "state") {
        send({ type: "serverEvent", epoch: streamEpoch, event });
        return;
      }
      const remote = {
        ...event.status,
        management_latency_ms: event.management_latency_ms ?? undefined,
      };
      send({ type: "serverEvent", epoch: streamEpoch, event: { kind: "status", remote, mode: event.mode, at: Date.now() } });
      if (remote.caller_role) {
        setServers((profiles) => {
          let changed = false;
          const next = profiles.map((profile) => {
            if (profile.id !== streamServer) return profile;
            const administrator = Boolean(remote.caller_administrator);
            const deviceId = remote.caller_device_id ?? profile.device_id;
            if (
              profile.role === remote.caller_role &&
              profile.administrator === administrator &&
              profile.device_id === deviceId
            )
              return profile;
            changed = true;
            return {
              ...profile,
              role: remote.caller_role!,
              administrator,
              device_id: deviceId,
            };
          });
          return changed ? next : profiles;
        });
      }
    });
    return () => { open = false; stop(); };
  }, [platform, streamServer, streamEpoch, send, setServers]);

  useEffect(() => {
    if ((platform !== "desktop" && platform !== "android")) return;
    let stop: (() => void) | undefined;
    const cancel = () => {
      stop?.();
      stop = undefined;
      ++generation.current;
      traffic.current = null;
    };
    const resume = () => {
      if (document.hidden) {
        if (!stop) return;
        cancel();
        trafficUpdates.publish(null);
        send({ type: "visibility", visible: false });
        return;
      }
      if (stop) return;
      send({ type: "visibility", visible: true });
      if (api.watchLocalStatus) {
        let open = true;
        const timer = window.setTimeout(() => send({ type: "timer" }), LOCAL_READ_TIMEOUT_MS);
        const unwatch = api.watchLocalStatus(event => {
          if (!open) return; // a late event from a cancelled watch
          window.clearTimeout(timer);
          receiveLocal(++generation.current, event.stale ? null : event.status);
        });
        stop = () => { open = false; window.clearTimeout(timer); unwatch(); };
      } else {
        let active = true;
        let timer: number | undefined;
        const poll = async () => {
          await refreshStatus();
          if (active) timer = window.setTimeout(() => void poll(), 4_000);
        };
        stop = () => { active = false; window.clearTimeout(timer); };
        void poll();
      }
    };
    resume();
    window.addEventListener("focus", resume);
    document.addEventListener("visibilitychange", resume);
    return () => {
      cancel();
      window.removeEventListener("focus", resume);
      document.removeEventListener("visibilitychange", resume);
    };
  }, [platform, refreshStatus, receiveLocal, send, trafficUpdates]);

  const { localFeed, serverFeed } = feed;
  const freshness: StatusFreshness = useMemo(() => feedFreshness({ localFeed, serverFeed }), [localFeed, serverFeed]);
  return {
    trafficUpdates,
    localStatus: feed.local,
    serverStatus: feed.remote,
    refreshStatus,
    freshness,
  };
}
