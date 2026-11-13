import type { SetStateAction } from "react";
import type { ClientPlatform, ServerProfile } from "./types";

/** Why the ready workspace shows a notice above it: a reload failed, or the tray named an unknown server. */
export type BootNotice = "profiles" | "trayServer";

export type BootState =
  /** Asking the native side which platform this is, then reading the saved servers. */
  | { kind: "detecting"; platform: ClientPlatform | null }
  | { kind: "platformFailed" }
  /** The saved servers couldn't be read and none are known: a problem to fix, not a first launch. */
  | { kind: "storeFailed"; platform: ClientPlatform }
  | { kind: "empty"; platform: ClientPlatform }
  | { kind: "ready"; platform: ClientPlatform; servers: ServerProfile[]; selectedId: string; notice: BootNotice | null };

export type BootAction =
  | { type: "detect" }
  | { type: "platformDetected"; platform: ClientPlatform }
  | { type: "platformFailed" }
  /** Reading the saved servers again, e.g. Retry on the store problem. */
  | { type: "reload" }
  | { type: "serversLoaded"; servers: ServerProfile[]; select?: string }
  | { type: "serversFailed" }
  /** Updates from the status stream (endpoint changes) and other in-place edits of the list. */
  | { type: "serversChanged"; update: SetStateAction<ServerProfile[]> }
  | { type: "select"; id: string }
  | { type: "notice"; notice: BootNotice | null };

export const initialBoot: BootState = { kind: "detecting", platform: null };

export function bootPlatform(state: BootState): ClientPlatform | null {
  return state.kind === "platformFailed" ? null : state.platform;
}

function withServers(platform: ClientPlatform, servers: ServerProfile[], selectedId: string | undefined, notice: BootNotice | null): BootState {
  if (!servers.length) return { kind: "empty", platform };
  const selected = servers.some(server => server.id === selectedId) ? selectedId! : servers[0].id;
  return { kind: "ready", platform, servers, selectedId: selected, notice };
}

export function bootReducer(state: BootState, action: BootAction): BootState {
  switch (action.type) {
    case "detect":
      return initialBoot;
    case "platformDetected":
      return state.kind === "detecting" ? { kind: "detecting", platform: action.platform } : state;
    case "platformFailed":
      return state.kind === "detecting" ? { kind: "platformFailed" } : state;
    case "reload":
      return state.kind === "storeFailed" ? { kind: "detecting", platform: state.platform } : state;
    case "serversLoaded": {
      const platform = bootPlatform(state);
      if (!platform) return state;
      const selected = action.select ?? (state.kind === "ready" ? state.selectedId : undefined);
      return withServers(platform, action.servers, selected, null);
    }
    case "serversFailed":
      if (state.kind === "ready") return { ...state, notice: "profiles" };
      // A failed reload of an empty list is as much a store problem as a failed first read.
      return state.kind === "detecting" && state.platform || state.kind === "empty" ? { kind: "storeFailed", platform: state.platform! } : state;
    case "serversChanged":
      if (state.kind !== "ready") return state;
      return withServers(state.platform, typeof action.update === "function" ? action.update(state.servers) : action.update, state.selectedId, state.notice);
    case "select":
      return state.kind === "ready" && state.servers.some(server => server.id === action.id) ? { ...state, selectedId: action.id } : state;
    case "notice":
      return state.kind === "ready" ? { ...state, notice: action.notice } : state;
  }
}
