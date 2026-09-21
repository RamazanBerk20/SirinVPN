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

pub fn setup(app: &mut tauri::App) -> Result<(), Box<dyn std::error::Error>> {
    crate::app_preferences::setup(app)?;
    crate::wifi_automation::start(app.handle().clone());
    let tray_ready = crate::desktop_tray::create(app).is_ok();
    let state = app.state::<PreferencesState>();
    state.tray_available.store(tray_ready, Ordering::Relaxed);
    let preferences = state.current();
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
        if preferences.launch_minimized && preferences.close_to_tray && tray_ready {
            if window.hide().is_err() {
                show_main(app.handle());
            }
        } else {
            window.show()?;
            if preferences.launch_minimized {
                let _ = window.minimize();
            }
        }
    }
    Ok(())
}
