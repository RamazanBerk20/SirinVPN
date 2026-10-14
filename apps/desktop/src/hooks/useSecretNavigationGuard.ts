import { t } from "../i18n";
import { useEffect, type RefObject } from "react";
import { registerNavigationGuard } from "../lib/navigationGuard";

export function useSecretNavigationGuard(pending: boolean, scope: RefObject<HTMLElement | null>, abandon: () => void, busy = false) {
  useEffect(() => {
    if (!pending) return;
    let released = false;
    const check = () => {
      if (released) return true;
      if (busy) return false;
      if (!window.confirm(t("app.recoveryKeyGuard"))) return false;
      released = true;
      abandon();
      return true;
    };
    const unregister = registerNavigationGuard(check);
    const click = (event: MouseEvent) => {
      if (!(event.target instanceof Element) || scope.current?.contains(event.target) || event.target.closest('[role="dialog"]')) return;
      if (event.target.closest("button, a") && !check()) { event.preventDefault(); event.stopImmediatePropagation(); }
    };
    const hash = window.location.hash;
    const back = (event: PopStateEvent) => { if (!check()) { event.stopImmediatePropagation(); window.history.pushState(null, "", hash || "#home"); } };
    window.addEventListener("popstate", back, true);
    const unload = (event: BeforeUnloadEvent) => { event.preventDefault(); event.returnValue = ""; };
    document.addEventListener("click", click, true);
    window.addEventListener("beforeunload", unload);
    let active = true;
    let stop: (() => void) | undefined;
    void import("@tauri-apps/api/window").then(({ getCurrentWindow }) => {
      const appWindow = getCurrentWindow();
      let closing = false;
      // destroy() is not granted, which keeps close-to-tray intact. Hold every request;
      // once released, close again only after this listener is gone, so it cannot loop.
      const listening: Promise<() => void> = appWindow.onCloseRequested((event) => {
        event.preventDefault();
        if (closing || !check()) return;
        closing = true;
        void listening.then((unlisten) => unlisten()).then(() => appWindow.close()).catch(() => { closing = false; });
      });
      return listening;
    }).then((unlisten) => { if (active) stop = unlisten; else unlisten(); }).catch(() => {});
    return () => { active = false; stop?.(); unregister(); document.removeEventListener("click", click, true); window.removeEventListener("popstate", back, true); window.removeEventListener("beforeunload", unload); };
  }, [pending, scope, abandon, busy]);
}
