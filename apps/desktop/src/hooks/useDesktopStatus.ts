import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
  type Dispatch,
  type SetStateAction,
} from "react";
import { api } from "../api";
import { withTrafficRates, type TrafficSample } from "./trafficSample";
import type {
  ClientPlatform,
  LocalTunnelStatus,
  ServerProfile,
  ServerStatus,
} from "../types";

import { TrafficStore, localControlKey } from "./trafficStore";

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
export function useDesktopStatus(
  platform: ClientPlatform | null,
  setServers: Dispatch<SetStateAction<ServerProfile[]>>,
) {
  const [snapshot, setSnapshot] = useState<{
    local: LocalTunnelStatus;
    remote: ServerStatus | null;
  }>({ local: { ...emptyLocalStatus, state: "unknown" }, remote: null });
  const [freshness, setFreshness] = useState<StatusFreshness>({
    refreshing: true,
    updatedAt: null,
    management: "idle",
  });
  const traffic = useRef<TrafficSample | null>(null);
  const trafficUpdates = useMemo(() => new TrafficStore<LocalTunnelStatus>(), []);
  const generation = useRef(0);
  const endpointCheckpoint = useRef("");
  const activeServer = useRef<string | null>(null);
  const streamGeneration = useRef(0);
  const [streamEpoch, setStreamEpoch] = useState(0);
  const refreshStatus = useCallback(async (supplied?: LocalTunnelStatus, stale = false) => {
    const request = ++generation.current;
    if (!supplied) setFreshness((previous) => ({ ...previous, refreshing: true }));
    try {
      const raw = supplied ?? await api.localStatus();
      if (stale) throw new Error("The last local status is stale");
      if (request !== generation.current) return;
      if (raw.endpoint_checkpoint) {
        const key = `${raw.endpoint_checkpoint.claims.server_id}:${raw.endpoint_checkpoint.claims.generation}`;
        if (endpointCheckpoint.current !== key) {
          endpointCheckpoint.current = key;
          // Profile metadata must not delay publishing an already-read tunnel state.
          void api.listServers().then(profiles => { if (endpointCheckpoint.current === key) setServers(profiles); }).catch(() => { endpointCheckpoint.current = ""; });
        }
      }
      const at = performance.now();
      const local = withTrafficRates(raw, at, traffic.current);
      traffic.current = { local, at };
      trafficUpdates.publish(local);
      const serverId = local.state === "connected" ? local.server_id : null;
      const changed = activeServer.current !== serverId;
      if (changed) {
        activeServer.current = serverId;
        ++streamGeneration.current;
        setStreamEpoch((previous) => previous + 1);
      }
      setFreshness((previous) => {
        if (!previous.refreshing && !changed) return previous;
        return {
        ...previous,
        refreshing: false,
        management: serverId
          ? changed
            ? "refreshing"
            : previous.management
          : "idle",
        updatedAt: serverId && !changed ? previous.updatedAt : null,
        mode: serverId && !changed ? previous.mode : undefined,
      }; });
      setSnapshot((previous) => localControlKey(previous.local) === localControlKey(local) ? previous : ({
        local,
        remote:
          local.state === "connected" &&
          local.server_id === previous.local.server_id
            ? previous.remote
            : null,
      }));
    } catch {
      if (request === generation.current) {
        traffic.current = null;
        activeServer.current = null;
        ++streamGeneration.current;
        setStreamEpoch((previous) => previous + 1);
        setSnapshot((previous) => ({
          local: {
            ...previous.local,
            state: "unknown",
            rx_bytes_per_second: undefined,
            tx_bytes_per_second: undefined,
          },
          remote: null,
        }));
        setFreshness({
          refreshing: false,
          management: "unavailable",
          updatedAt: null,
        });
      }
    }
  }, []);

  const connectedServerId =
    snapshot.local.state === "connected" ? snapshot.local.server_id : null;
  useEffect(() => {
    if ((platform !== "desktop" && platform !== "android") || !connectedServerId || document.hidden ||
      activeServer.current !== connectedServerId) return;
    const stream = ++streamGeneration.current;
    const stop = api.watchServerStatus(connectedServerId, (event) => {
      if (
        stream !== streamGeneration.current ||
        activeServer.current !== connectedServerId
      )
        return;
      if (event.kind === "state") {
        setSnapshot((previous) => ({ ...previous, remote: null }));
        setFreshness((previous) => ({
          ...previous,
          management:
            event.state === "connecting" ? "refreshing" : "reconnecting",
          updatedAt: null,
          mode: undefined,
        }));
        return;
      }
      const remote = {
        ...event.status,
        management_latency_ms: event.management_latency_ms ?? undefined,
      };
      setSnapshot((previous) => ({ ...previous, remote }));
      setFreshness((previous) => ({
        ...previous,
        management: "ready",
        updatedAt: Date.now(),
        mode: event.mode,
      }));
      if (remote.caller_role) {
        setServers((profiles) => {
          let changed = false;
          const next = profiles.map((profile) => {
            if (profile.id !== connectedServerId) return profile;
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
    return () => {
      ++streamGeneration.current;
      stop();
    };
  }, [platform, connectedServerId, streamEpoch, setServers]);

  useEffect(() => {
    if ((platform !== "desktop" && platform !== "android")) return;
    let stop: (() => void) | undefined;
    const cancel = () => {
      stop?.();
      stop = undefined;
      ++generation.current;
      ++streamGeneration.current;
      activeServer.current = null;
      traffic.current = null;
    };
    const resume = () => {
      if (document.hidden) {
        if (!stop) return;
        cancel();
        trafficUpdates.publish(null);
        setStreamEpoch((previous) => previous + 1);
        setSnapshot((previous) => ({ local: { ...previous.local, state: "unknown" }, remote: null }));
        setFreshness((previous) => ({ ...previous, management: "idle", updatedAt: null, mode: undefined }));
        return;
      }
      if (stop) return;
      // A fresh local reading must select the VPS stream after every resume.
      activeServer.current = null;
      if (api.watchLocalStatus) {
        stop = api.watchLocalStatus(event => {
          void refreshStatus(event.status as LocalTunnelStatus | undefined ?? { ...emptyLocalStatus, state: "unknown" }, event.stale);
        });
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
  }, [platform, refreshStatus, trafficUpdates]);

  return {
    trafficUpdates,
    localStatus: snapshot.local,
    serverStatus: snapshot.remote,
    refreshStatus,
    freshness,
  };
}
