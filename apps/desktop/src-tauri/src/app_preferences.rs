//! Device-local UI preferences; never included in VPN identities or server backups.
mod store;
pub use store::AppPreferences;

use serde::Serialize;
use std::{
    path::PathBuf,
    sync::{
        Mutex,
        atomic::{AtomicBool, Ordering},
    },
};
use tauri::{AppHandle, Manager, State, plugin::PermissionState};
use tauri_plugin_notification::NotificationExt;

pub struct PreferencesState {
    path: PathBuf,
    data: Mutex<Result<AppPreferences, String>>,
    pub tray_available: AtomicBool,
}

impl PreferencesState {
    pub fn current(&self) -> AppPreferences {
        self.data
            .lock()
            .ok()
            .and_then(|data| data.as_ref().ok().cloned())
            .unwrap_or_default()
    }
}

#[derive(Serialize)]
pub struct PreferencesSnapshot {
    preferences: AppPreferences,
    startup_available: bool,
    tray_available: bool,
    notification_permission: PermissionState,
}

pub fn setup(app: &mut tauri::App) -> Result<(), Box<dyn std::error::Error>> {
    crate::connection_preferences::setup(app)?;
    let path = app.path().app_config_dir()?.join("app-preferences.json");
    let data = store::read(&path).map_err(|_| {
        "App preferences could not be read. Your existing settings were preserved.".to_owned()
    });
    app.manage(PreferencesState {
        path,
        data: Mutex::new(data),
        tray_available: AtomicBool::new(false),
    });
    Ok(())
}

fn snapshot(
    app: &AppHandle,
    state: &PreferencesState,
    mut preferences: AppPreferences,
) -> PreferencesSnapshot {
    let (startup_available, start_on_login) = {
        let startup = crate::desktop_startup::is_enabled(app).ok();
        (startup.is_some(), startup.unwrap_or(false))
    };
    // The system's startup registration is authoritative, including changes made outside the app.
    preferences.start_on_login = start_on_login;
    PreferencesSnapshot {
        preferences,
        startup_available,
        tray_available: state.tray_available.load(Ordering::Relaxed),
        notification_permission: app
            .notification()
            .permission_state()
            .unwrap_or(PermissionState::Denied),
    }
}

#[tauri::command]
pub async fn get_app_preferences(
    app: AppHandle,
    state: State<'_, PreferencesState>,
) -> Result<PreferencesSnapshot, String> {
    let data = state
        .data
        .lock()
        .map_err(|_| "App preferences are unavailable.")?;
    let preferences = data.as_ref().map_err(Clone::clone)?.clone();
    drop(data);
    Ok(snapshot(&app, &state, preferences))
}

#[tauri::command]
pub async fn set_app_preferences(
    app: AppHandle,
    state: State<'_, PreferencesState>,
    preferences: AppPreferences,
) -> Result<PreferencesSnapshot, String> {
    let mut data = state
        .data
        .lock()
        .map_err(|_| "App preferences are unavailable.")?;
    let previous = data.as_ref().map_err(Clone::clone)?;
    if preferences.close_to_tray
        && !previous.close_to_tray
        && !state.tray_available.load(Ordering::Relaxed)
    {
        return Err("A system tray is unavailable. The window will stay accessible.".to_owned());
    }
    if preferences.notifications
        && !previous.notifications
        && app.notification().permission_state().ok() != Some(PermissionState::Granted)
    {
        return Err("Allow SirinVPN notifications in system settings first.".to_owned());
    }
    let previous_startup = crate::desktop_startup::is_enabled(&app).ok();
    match previous_startup {
        Some(enabled) if enabled != preferences.start_on_login => {
            change_startup(&app, preferences.start_on_login)?
        }
        None if preferences.start_on_login => {
            return Err("System startup settings are unavailable.".to_owned());
        }
        _ => {}
    }
    if store::write(&state.path, &preferences).is_err() {
        if let Some(enabled) = previous_startup
            && enabled != preferences.start_on_login
            && change_startup(&app, enabled).is_err()
        {
            return Err("Preferences could not be saved and startup could not be restored. Check your system's startup applications.".to_owned());
        }
        return Err(
            "App preferences could not be saved. Previous settings remain active.".to_owned(),
        );
    }
    *data = Ok(preferences.clone());
    drop(data);
    let result = snapshot(&app, &state, preferences);
    Ok(result)
}

fn change_startup(app: &AppHandle, enabled: bool) -> Result<(), String> {
    crate::desktop_startup::set_enabled(app, enabled).map_err(|_| {
        "Could not change startup registration. Check your system's startup applications."
            .to_owned()
    })
}

#[tauri::command]
pub async fn request_notification_permission(app: AppHandle) -> Result<PermissionState, String> {
    // Permission may have changed outside the app since the last snapshot.
    if app.notification().permission_state().ok() == Some(PermissionState::Granted) {
        return Ok(PermissionState::Granted);
    }
    app.notification()
        .request_permission()
        .map_err(|_| "Notification permission could not be requested.".to_owned())
}

#[tauri::command]
pub async fn test_notification(app: AppHandle) -> Result<(), String> {
    crate::app_notifications::show(
        app,
        7401,
        "Notifications are ready. Connection alerts will appear here.",
    )
    .await
}
