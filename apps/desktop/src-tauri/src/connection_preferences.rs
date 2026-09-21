mod store;
use sirinvpn_protocol::ServerId;
pub use store::{ConnectionPreferenceStore, ConnectionPreferences};
use tauri::{AppHandle, Manager};

pub fn setup(app: &mut tauri::App) -> Result<(), Box<dyn std::error::Error>> {
    app.manage(ConnectionPreferenceStore::new(
        app.path().app_config_dir()?.join("connection-preferences"),
    ));
    Ok(())
}

async fn require_profile(app: &AppHandle, id: ServerId) -> Result<(), String> {
    {
        crate::identity::find_profile(&app.state::<crate::AppState>().paths, &id.to_string())?;
    }
    Ok(())
}

#[tauri::command]
pub async fn get_connection_preferences(
    app: AppHandle,
    server_id: String,
) -> Result<ConnectionPreferences, String> {
    let id = server_id
        .parse::<ServerId>()
        .map_err(|_| "The local server ID is invalid.")?;
    require_profile(&app, id).await?;
    app.state::<ConnectionPreferenceStore>().get(id)
}

#[tauri::command]
pub async fn set_connection_preferences(
    app: AppHandle,
    server_id: String,
    preferences: ConnectionPreferences,
) -> Result<ConnectionPreferences, String> {
    let id = server_id
        .parse::<ServerId>()
        .map_err(|_| "The local server ID is invalid.")?;
    require_profile(&app, id).await?;
    if preferences.android_applications.is_some() {
        return Err("Android application routing can only be configured on Android.".into());
    }
    app.state::<ConnectionPreferenceStore>()
        .set(id, preferences)
}

pub fn forget(app: &AppHandle, server_id: &str) -> Result<(), String> {
    let id = server_id
        .parse::<ServerId>()
        .map_err(|_| "The local server ID is invalid.")?;
    app.state::<ConnectionPreferenceStore>().forget(id)
}
