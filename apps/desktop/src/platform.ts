import { Channel, invoke as tauriInvoke } from "@tauri-apps/api/core";
import type { LocalStatusEvent, ServerStatus, ServerStatusEvent } from "./types";

const DEMO_KEY = "sirin.demo";
/** A plain browser (no Tauri bridge), such as `pnpm dev`; the real app always has the bridge. */
const inBrowser = typeof window !== "undefined" && !("__TAURI_INTERNALS__" in window);
// In a plain browser only, `?demo=1&platform=android&role=admin&future=1` opens the demo; the values
// are kept for the tab's session and dropped from the address. The real app never reads its address.
if (inBrowser) {
  try {
    const query = new URLSearchParams(window.location.search);
    const keys = { demo: DEMO_KEY, platform: "sirin.demo.platform", role: "sirin.demo.role", future: "sirin.demo.future" };
    for (const [name, key] of Object.entries(keys)) { const value = query.get(name); if (value !== null) sessionStorage.setItem(key, value); query.delete(name); }
    const search = query.toString();
    if (search !== window.location.search.slice(1)) window.history.replaceState(window.history.state, "", `${window.location.pathname}${search ? `?${search}` : ""}${window.location.hash}`);
  } catch { /* No session storage: no demo. */ }
}
/** Fixed for the page's life: entering or leaving the demo reloads, so no state crosses between demo and real use. */
export const isDemo = (() => { try { return sessionStorage.getItem(DEMO_KEY) === "1"; } catch { return false; } })();
/** The demo may pick the phone layout (`sirin.demo.platform` = "android"); the real app follows its user agent. */
export const isAndroid = typeof navigator !== "undefined" && /Android/i.test(navigator.userAgent)
  || isDemo && (() => { try { return sessionStorage.getItem("sirin.demo.platform") === "android"; } catch { return false; } })();
/** The demo in a plain browser: native windows, dialogs and Android Back are absent there. */
export const browserDemo = isDemo && inBrowser;
/** Android TV: no pointer, only a D-pad. Pages then start focus on their first control. */
export const dpadOnly = isAndroid && window.matchMedia?.("(pointer: none)").matches === true;

export function setDemo(enabled: boolean) {
  try { if (enabled) sessionStorage.setItem(DEMO_KEY, "1"); else sessionStorage.removeItem(DEMO_KEY); } catch { return; }
  window.location.reload();
}

/** A coded desktop rejection (`{message, code, params}`) becomes an Error carrying `code` and `params`, as on Android. */
function rejection(reason: unknown): unknown {
  if (reason instanceof Error || !reason || typeof reason !== "object") return reason;
  const { message, code, params } = reason as { message?: unknown; code?: unknown; params?: unknown };
  return typeof message === "string" ? Object.assign(new Error(message), { code, params }) : reason;
}

export async function invoke<T>(command: string, args: Record<string, unknown> = {}): Promise<T> {
  // Every app command goes to sample data; the native bridge never sees a demo request.
  if (isDemo) return (await import("./demo")).demoInvoke<T>(command, args);
  if (!isAndroid) return tauriInvoke<T>(command, args).catch((reason: unknown) => { throw rejection(reason); });
  const result = await tauriInvoke<{ ok?: T; error?: string; code?: string; params?: unknown }>("android_call", { command, args });
  // Same shape as a desktop rejection: appError reads `code` and `params`.
  if (result.error) throw Object.assign(new Error(result.error), { code: result.code, params: result.params });
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
  // The only direct native calls; demo status comes through the routed subscription instead.
  if (isDemo) return () => {};
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
