import { useEffect, useState } from "react";
import { getCurrentWindow } from "@tauri-apps/api/window";
import { Minus, Square, CopySimple, X } from "@phosphor-icons/react";
import { usePreferences } from "../features/settings/PreferencesProvider";

const edges: Parameters<
  ReturnType<typeof getCurrentWindow>["startResizeDragging"]
>[0][] = [
  "North",
  "South",
  "East",
  "West",
  "NorthEast",
  "NorthWest",
  "SouthEast",
  "SouthWest",
];

/** Window.close emits CloseRequested; the native tray policy remains authoritative. */
export function DesktopTitleBar() {
  const { snapshot } = usePreferences();
  const [maximized, setMaximized] = useState(false);
  const [error, setError] = useState("");
  useEffect(() => {
    document.documentElement.dataset.windowChrome = "custom";
    let disposed = false;
    let unlisten: (() => void) | undefined;
    const sync = async () => {
      try {
        const value = await getCurrentWindow().isMaximized();
        if (!disposed) setMaximized(value);
      } catch {
        /* A browser preview has no native window. */
      }
    };
    void sync();
    void (async () => {
      try {
        const release = await getCurrentWindow().onResized(() => void sync());
        if (disposed) release();
        else unlisten = release;
      } catch {
        /* Native window controls remain available if event registration fails. */
      }
    })();
    return () => {
      disposed = true;
      unlisten?.();
      delete document.documentElement.dataset.windowChrome;
    };
  }, []);

  const run = async (action: "minimize" | "toggleMaximize" | "close") => {
    setError("");
    try {
      await getCurrentWindow()[action]();
    } catch {
      setError("Window action failed. Try your desktop's window controls.");
    }
  };
  const closeLabel =
    snapshot?.preferences.close_to_tray && snapshot.tray_available
      ? "Close to tray · VPN keeps running"
      : "Quit app · VPN keeps running";
  return (
    <>
      <header className="desktop-titlebar" aria-label="Application window">
        <div className="titlebar-drag-region" data-tauri-drag-region>
          <span data-tauri-drag-region>SirinVPN</span>
          <span className="titlebar-error" role="status">
            {error}
          </span>
        </div>
        <div className="titlebar-controls">
          <button
            type="button"
            aria-label="Minimize window"
            title="Minimize"
            onClick={() => void run("minimize")}
          >
            <Minus size={16} />
          </button>
          <button
            type="button"
            aria-label={maximized ? "Restore window" : "Maximize window"}
            title={maximized ? "Restore" : "Maximize"}
            onClick={() => void run("toggleMaximize")}
          >
            {maximized ? <CopySimple size={15} /> : <Square size={14} />}
          </button>
          <button
            type="button"
            className="titlebar-close"
            aria-label={closeLabel}
            title={closeLabel}
            onClick={() => void run("close")}
          >
            <X size={18} />
          </button>
        </div>
      </header>
      {!maximized &&
        edges.map((direction) => (
          <div
            key={direction}
            className="window-resize-edge"
            data-edge={direction}
            aria-hidden="true"
            onMouseDown={(event) => {
              if (event.button !== 0) return;
              event.preventDefault();
              void (async () => {
                try {
                  await getCurrentWindow().startResizeDragging(direction);
                } catch {
                  setError(
                    "Window resizing is unavailable. Use your desktop's resize shortcut.",
                  );
                }
              })();
            }}
          />
        ))}
    </>
  );
}
