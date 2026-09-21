import { useEffect } from "react";
import { onBackButtonPress } from "@tauri-apps/api/app";
import { invoke, isAndroid } from "../platform";
import { confirmNavigation } from "../lib/navigationGuard";

/** Android owns the gesture; existing dialogs and navigation guards own dismissal. */
export function useAndroidBack() {
  useEffect(() => {
    if (!isAndroid) return;
    let disposed = false;
    const listener = onBackButtonPress(({ canGoBack }) => {
      if (disposed) return;
      if (document.querySelector('[role="dialog"][data-state="open"], [role="menu"][data-state="open"], [role="listbox"][data-state="open"]')) {
        document.dispatchEvent(new KeyboardEvent("keydown", { key: "Escape", bubbles: true, cancelable: true }));
      } else if (confirmNavigation()) {
        // Android WebView's native history can omit same-document pushState.
        if (window.history.state?.sirinDepth > 0 || canGoBack) window.history.back();
        else void invoke("android_close_ui");
      }
    });
    return () => { disposed = true; void listener.then(value => value.unregister()).catch(() => {}); };
  }, []);
}
