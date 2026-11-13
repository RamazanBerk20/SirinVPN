import type { LocalTunnelStatus } from "../../types";
import type { PendingCommand } from "./connectionCommands";

/** What the tunnel itself reports, before anything the UI has asked for. Mirrors the native `TunnelPhase`. */
export type TunnelPhase = "unknown" | "disconnected" | "connecting" | "connected" | "reconnecting" | "waiting_for_user" | "interrupted";
export interface TunnelReport {
  phase: TunnelPhase;
  /** The tunnel carries traffic (also while it re-establishes a session on top of a working one). */
  established: boolean;
}

/**
 * THE adapter from native status to a phase. It reads the native `phase`; only a status without one
 * (an older service or native layer) falls back to the separate state flags.
 */
export function tunnelReport(local: LocalTunnelStatus): TunnelReport {
  const kind = local.phase?.kind;
  if (kind) {
    const established = kind === "connected";
    switch (kind) {
      case "idle": return { phase: "disconnected", established };
      case "connecting": return { phase: "connecting", established };
      case "connected": return { phase: "connected", established };
      case "recovering": return { phase: "reconnecting", established };
      case "paused": return { phase: "waiting_for_user", established };
      case "unhealthy": return { phase: local.phase?.recovering || local.auto_reconnect_enabled ? "reconnecting" : "interrupted", established };
    }
  }
  const established = local.state === "connected";
  if (local.state === "unknown") return { phase: "unknown", established };
  if (local.state === "disconnected") return { phase: "disconnected", established };
  if (!local.waiting_for_user && (local.recovery_in_progress === true || local.state === "degraded" && local.auto_reconnect_enabled))
    return { phase: "reconnecting", established };
  if (established) return { phase: "connected", established };
  if (local.waiting_for_user) return { phase: "waiting_for_user", established };
  if (local.state === "connecting") return { phase: "connecting", established };
  return { phase: local.auto_reconnect_enabled ? "reconnecting" : "interrupted", established };
}

/** The connection as one server's views show it: tunnel phase for this server, overridden by a pending command. */
export type ConnectionView =
  | { phase: "unknown" }
  | { phase: "idle"; otherServer: boolean }
  | { phase: "starting"; by: "user" | "tunnel" }
  | { phase: "up" }
  | { phase: "reconnecting" }
  | { phase: "interrupted"; waitingForUser: boolean }
  | { phase: "stopping" };

export function connectionView(local: LocalTunnelStatus, serverId: string, pending: PendingCommand | null): ConnectionView {
  const tunnel = tunnelReport(local);
  const here = local.server_id === serverId;
  // A command without a server (from a dialog) acts on whichever server the tunnel runs.
  if (pending && (pending.serverId === serverId || pending.serverId === null && here))
    return pending.kind === "disconnect" ? { phase: "stopping" } : { phase: "starting", by: "user" };
  if (tunnel.phase === "unknown") return { phase: "unknown" };
  if (!here || tunnel.phase === "disconnected") return { phase: "idle", otherServer: local.server_id !== null && !here };
  switch (tunnel.phase) {
    case "connecting": return { phase: "starting", by: "tunnel" };
    case "connected": return { phase: "up" };
    case "reconnecting": return { phase: "reconnecting" };
    case "waiting_for_user": return { phase: "interrupted", waitingForUser: true };
    case "interrupted": return { phase: "interrupted", waitingForUser: false };
  }
}
