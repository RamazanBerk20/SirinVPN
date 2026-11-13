import type { LocalTunnelStatus, ServerStatus } from "../types";
import { localControlKey } from "./trafficStore";

/**
 * The local tunnel reading. `subscribing`: a reading is on its way; `stale`: it did not come in time, the last
 * good reading stays shown; `failed`: the helper answered with an error or no status.
 */
export type LocalFeed = { state: "paused" } | { state: "subscribing" } | { state: "live" } | { state: "stale" } | { state: "failed" };
/** The VPS stream of the connected server. `epoch` names one subscription; events from older ones are dropped. */
export type ServerFeed =
  | { state: "off" }
  | { state: "connecting"; serverId: string; epoch: number }
  | { state: "live"; serverId: string; epoch: number; mode?: "live" | "polling"; updatedAt: number }
  | { state: "reconnecting"; serverId: string; epoch: number };

export interface StatusFeed {
  local: LocalTunnelStatus;
  remote: ServerStatus | null;
  localFeed: LocalFeed;
  serverFeed: ServerFeed;
  /** Last subscription number handed out. */
  epoch: number;
}

export type LocalEvent = { kind: "reading"; local: LocalTunnelStatus } | { kind: "failed" };
export type ServerEvent =
  | { kind: "state"; state: "connecting" | "reconnecting" }
  | { kind: "status"; remote: ServerStatus; mode?: "live" | "polling"; at: number };

export type StatusFeedAction =
  | { type: "visibility"; visible: boolean }
  /** A local reading was requested. */
  | { type: "refresh" }
  | { type: "localEvent"; event: LocalEvent }
  | { type: "serverEvent"; epoch: number; event: ServerEvent }
  /** The requested local reading did not arrive in time. */
  | { type: "timer" };

export const initialStatusFeed = (local: LocalTunnelStatus): StatusFeed =>
  ({ local, remote: null, localFeed: { state: "subscribing" }, serverFeed: { state: "off" }, epoch: 0 });

const serverOf = (feed: ServerFeed) => feed.state === "off" ? null : feed.serverId;

export function statusFeedReducer(state: StatusFeed, action: StatusFeedAction): StatusFeed {
  switch (action.type) {
    case "visibility":
      if (action.visible) return state.localFeed.state === "paused" ? { ...state, localFeed: { state: "subscribing" } } : state;
      if (state.localFeed.state === "paused") return state;
      return { ...state, local: { ...state.local, state: "unknown" }, remote: null, localFeed: { state: "paused" }, serverFeed: { state: "off" } };
    case "refresh":
      return state.localFeed.state === "subscribing" ? state : { ...state, localFeed: { state: "subscribing" } };
    case "timer":
      return state.localFeed.state === "subscribing" ? { ...state, localFeed: { state: "stale" } } : state;
    case "localEvent": {
      if (action.event.kind === "failed")
        return { ...state, local: { ...state.local, state: "unknown", rx_bytes_per_second: undefined, tx_bytes_per_second: undefined },
          remote: null, localFeed: { state: "failed" }, serverFeed: { state: "off" } };
      const { local } = action.event;
      const serverId = local.state === "connected" ? local.server_id : null;
      const changed = serverOf(state.serverFeed) !== serverId;
      const sameControl = localControlKey(state.local) === localControlKey(local);
      // Traffic-only readings keep the same state object, so nothing re-renders for them.
      if (!changed && sameControl && state.localFeed.state === "live") return state;
      const epoch = changed && serverId ? state.epoch + 1 : state.epoch;
      return {
        local: sameControl ? state.local : local,
        remote: changed || !serverId ? null : state.remote,
        localFeed: { state: "live" },
        serverFeed: !serverId ? { state: "off" } : changed ? { state: "connecting", serverId, epoch } : state.serverFeed,
        epoch,
      };
    }
    case "serverEvent": {
      const feed = state.serverFeed;
      if (feed.state === "off" || feed.epoch !== action.epoch) return state;
      const { event } = action;
      if (event.kind === "state") return { ...state, remote: null, serverFeed: { state: event.state, serverId: feed.serverId, epoch: feed.epoch } };
      return { ...state, remote: event.remote,
        serverFeed: { state: "live", serverId: feed.serverId, epoch: feed.epoch, mode: event.mode, updatedAt: event.at } };
    }
  }
}

/** The freshness callers read, derived from the two feeds. */
export function feedFreshness({ localFeed, serverFeed }: Pick<StatusFeed, "localFeed" | "serverFeed">) {
  return {
    refreshing: localFeed.state === "subscribing",
    updatedAt: serverFeed.state === "live" ? serverFeed.updatedAt : null,
    management: serverFeed.state === "off" ? localFeed.state === "failed" ? "unavailable" as const : "idle" as const
      : serverFeed.state === "connecting" ? "refreshing" as const : serverFeed.state === "live" ? "ready" as const : "reconnecting" as const,
    mode: serverFeed.state === "live" ? serverFeed.mode : undefined,
  };
}
