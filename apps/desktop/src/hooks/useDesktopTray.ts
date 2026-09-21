import { useEffect, useRef } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";

export interface DesktopNavigation {
  sequence: number;
  destination:
    | "home"
    | "servers"
    | "add_server"
    | "settings"
    | "connection"
    | "diagnostics"
    | "component_update";
  server_id: string | null;
}

/** Native connection actions run without this hook. This only opens app pages. */
export function useDesktopTray(
  ready: boolean,
  selectedId: string | null,
  onNavigate: (request: DesktopNavigation) => void,
) {
  const handler = useRef(onNavigate);
  const handled = useRef<number | null>(null);
  handler.current = onNavigate;
  useEffect(() => {
    if (!ready) return;
    void invoke("desktop_selection", { serverId: selectedId }).catch(() => {});
  }, [ready, selectedId]);
  useEffect(() => {
    if (!ready) return;
    let disposed = false;
    let unlisten: (() => void) | undefined;
    const consume = async () => {
      const request = await invoke<DesktopNavigation | null>(
        "desktop_navigation",
      );
      if (!disposed && request) {
        if (handled.current !== request.sequence) {
          handled.current = request.sequence;
          handler.current(request);
        }
        await invoke("desktop_navigation_ack", { sequence: request.sequence });
      }
    };
    void listen("desktop-navigation", () => {
      void consume().catch(() => {});
    })
      .then((stop) => {
        if (disposed) {
          stop();
          return;
        }
        unlisten = stop;
        void consume().catch(() => {});
      })
      .catch(() => {});
    return () => {
      disposed = true;
      unlisten?.();
    };
  }, [ready]);
}
