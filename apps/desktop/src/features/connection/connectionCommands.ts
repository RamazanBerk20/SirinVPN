import { useSyncExternalStore } from "react";
import { api } from "../../api";
import type { LocalTunnelStatus } from "../../types";
import { clearMembershipCache } from "../devices/membershipCache";

/** A tunnel command the UI has sent and the tunnel has not yet answered. */
export type PendingCommand = { id: number; kind: "connect" | "disconnect" | "resume"; serverId: string | null };

// One tunnel per device, so one shared slot: Home, the sidebar and every dialog read the same command.
let pending: PendingCommand | null = null;
let nextId = 0;
const listeners = new Set<() => void>();
const publish = (next: PendingCommand | null) => { pending = next; listeners.forEach((listener) => listener()); };

export function pendingCommand(): PendingCommand | null {
  return pending;
}

/** Marks `run` as the pending command until it settles; a later command replaces it. */
export async function runCommand<T>(kind: PendingCommand["kind"], serverId: string | null, run: () => Promise<T>): Promise<T> {
  const command = { id: ++nextId, kind, serverId };
  publish(command);
  try {
    return await run();
  } finally {
    if (pending?.id === command.id) publish(null);
  }
}

/** Every disconnect goes through here, so all views show "Disconnecting" and drop cached membership. */
export function disconnectTunnel(serverId: string | null): Promise<LocalTunnelStatus> {
  return runCommand("disconnect", serverId, () => { clearMembershipCache(); return api.disconnect(); });
}

export function usePendingCommand(): PendingCommand | null {
  return useSyncExternalStore((listener) => { listeners.add(listener); return () => listeners.delete(listener); }, pendingCommand, pendingCommand);
}
