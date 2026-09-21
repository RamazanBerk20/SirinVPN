import { Channel, invoke as tauriInvoke } from "@tauri-apps/api/core";
import type { LocalStatusEvent, ServerStatus, ServerStatusEvent } from "./types";

export const isAndroid = typeof navigator !== "undefined" && /Android/i.test(navigator.userAgent);

export async function invoke<T>(command: string, args: Record<string, unknown> = {}): Promise<T> {
  if (!isAndroid) return tauriInvoke<T>(command, args);
  const result = await tauriInvoke<{ ok?: T; error?: string }>("android_call", { command, args });
  if (result.error) throw new Error(result.error);
  return result.ok as T;
}

/** Presentation reads are cancelled when the shared foreground observer closes. */
export function watchAndroidServerStatus(serverId: string, callback: (event: ServerStatusEvent) => void): () => void {
  let active = true;
  let timer: ReturnType<typeof setTimeout> | undefined;
  const read = async () => {
    const started = performance.now();
    try {
      const status = await invoke<ServerStatus>("server_status", { serverId });
      if (active) callback({ kind: "status", status, mode: "polling", management_latency_ms: performance.now() - started });
    } catch { if (active) callback({ kind: "state", state: "reconnecting" }); }
    if (active) timer = setTimeout(() => { void read(); }, 3000);
  };
  void read();
  return () => { active = false; clearTimeout(timer); };
}

export function watchAndroidStatus(callback: (event: LocalStatusEvent) => void): () => void {
  let active = true;
  let sequence = -1;
  let generation = -1;
  const receive = (event: LocalStatusEvent) => {
    if (!active) return;
    if (event.stale) { callback(event); return; }
    if (event.generation < generation || event.generation === generation && event.sequence <= sequence) return;
    generation = event.generation; sequence = event.sequence; callback(event);
  };
  const channel = new Channel<LocalStatusEvent>();
  channel.onmessage = receive;
  const ready = tauriInvoke<void>("android_watch", { onEvent: channel })
    .then(() => invoke<LocalStatusEvent>("android_snapshot")).then(receive)
    .catch(() => { if (active) callback({ status: null, phase: "unknown", stale: true, sequence: 0, generation: 0 }); });
  return () => { active = false; void ready.finally(() => tauriInvoke("android_unwatch", { channelId: channel.id })).catch(() => {}); };
}
