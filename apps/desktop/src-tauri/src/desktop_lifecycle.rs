//! Desktop window lifetime is independent of the native VPN service.
use crate::app_preferences::PreferencesState;
use std::sync::atomic::Ordering;
use tauri::{AppHandle, Manager, WindowEvent};

pub fn show_main(app: &AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        // GTK3 cannot reliably deiconify on Wayland (xdg-shell has no unminimize
        // request or minimized-state event). Remap the same WebView on explicit
        // tray/launcher activation so a minimized app remains reachable.
        #[cfg(target_os = "linux")]
        if std::env::var_os("WAYLAND_DISPLAY").is_some()
            && std::env::var("GDK_BACKEND").as_deref() != Ok("x11")
        {
            let _ = window.hide();
        }
        let _ = window.show();
        let _ = window.unminimize();
        let _ = window.set_focus();
    }
}

/// Written by Restart now and consumed by the next launch: a restart the user asked for shows
/// the window even when the app normally starts hidden in the tray.
pub(crate) fn restart_marker(app: &AppHandle) -> std::path::PathBuf {
    app.state::<crate::AppState>()
        .paths
        .configuration_directory
        .join("show-after-restart")
}

/// Hidden in the tray only for a normal minimized launch that has a tray to come back from.
fn start_hidden(launch_minimized: bool, close_to_tray: bool, tray_ready: bool, restarted: bool) -> bool {
    launch_minimized && close_to_tray && tray_ready && !restarted
}

pub fn setup(app: &mut tauri::App) -> Result<(), Box<dyn std::error::Error>> {
    crate::app_preferences::setup(app)?;
    crate::wifi_automation::start(app.handle().clone());
    let tray_ready = crate::desktop_tray::create(app).is_ok();
    crate::local_status_stream::watch_native(app.handle().clone());
    let state = app.state::<PreferencesState>();
    state.tray_available.store(tray_ready, Ordering::Relaxed);
    let preferences = state.current();
    let restarted = std::fs::remove_file(restart_marker(app.handle())).is_ok();
    if let Some(window) = app.get_webview_window("main") {
        let handle = app.handle().clone();
        let closing_window = window.clone();
        window.on_window_event(move |event| {
            if let WindowEvent::CloseRequested { api, .. } = event {
                let state = handle.state::<PreferencesState>();
                if state.tray_available.load(Ordering::Relaxed)
                    && state.current().close_to_tray
                    && closing_window.hide().is_ok()
                {
                    api.prevent_close();
                }
            }
        });
        // Without a tray, minimized launch uses the taskbar so the app stays reachable.
        if start_hidden(
            preferences.launch_minimized,
            preferences.close_to_tray,
            tray_ready,
            restarted,
        ) {
            if window.hide().is_err() {
                show_main(app.handle());
            }
        } else {
            window.show()?;
            if preferences.launch_minimized && !restarted {
                let _ = window.minimize();
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::start_hidden;

    #[test]
    fn a_requested_restart_always_shows_the_window() {
        assert!(start_hidden(true, true, true, false));
        assert!(!start_hidden(true, true, true, true));
        assert!(!start_hidden(true, true, false, false));
        assert!(!start_hidden(true, false, true, false));
    }
}
