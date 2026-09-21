import { useEffect, type RefObject } from "react";
import { registerNavigationGuard } from "../lib/navigationGuard";

export function useSecretNavigationGuard(pending: boolean, scope: RefObject<HTMLElement | null>, abandon: () => void, busy = false) {
  useEffect(() => {
    if (!pending) return;
    let released = false;
    const check = () => {
      if (released) return true;
      if (busy) return false;
      if (!window.confirm("This recovery key cannot be retrieved again. Leave without confirming that you saved it? Any unsaved copy in this view will be cleared.")) return false;
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
    void import("@tauri-apps/api/window").then(({ getCurrentWindow }) => getCurrentWindow().onCloseRequested((event) => { if (!check()) event.preventDefault(); })).then((unlisten) => { if (active) stop = unlisten; else unlisten(); }).catch(() => {});
    return () => { active = false; stop?.(); unregister(); document.removeEventListener("click", click, true); window.removeEventListener("popstate", back, true); window.removeEventListener("beforeunload", unload); };
  }, [pending, scope, abandon, busy]);
}
