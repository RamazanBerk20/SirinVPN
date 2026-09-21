//! App-owned delivery keeps Linux sender metadata separate from the message title.
use crate::app_preferences::PreferencesState;
use tauri::{AppHandle, Manager};

pub async fn show(app: AppHandle, id: i32, body: &'static str) -> Result<(), String> {
    if !app.state::<PreferencesState>().current().notifications {
        return Err("Enable notifications first.".to_owned());
    }
    #[cfg(target_os = "linux")]
    {
        // File access and the acknowledged D-Bus call must not block the UI thread.
        tauri::async_runtime::spawn_blocking(move || linux::show(&app, id, body))
            .await
            .map_err(|_| "The notification task could not finish.".to_owned())?
            .map_err(|_| "The system could not display a notification.".to_owned())
    }
    #[cfg(not(target_os = "linux"))]
    {
        use tauri_plugin_notification::NotificationExt;
        app.notification()
            .builder()
            .id(id)
            .title("SirinVPN")
            .body(body)
            .show()
            .map_err(|_| "The system could not display a notification.".to_owned())
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use anyhow::Result;
    use notify_rust::{Hint, Notification};
    use std::{fs, io::Write, os::unix::fs::DirBuilderExt};

    const ICON: &[u8] = include_bytes!("../icons/128x128.png");

    pub fn show(app: &AppHandle, _id: i32, body: &str) -> Result<()> {
        let directory = app.path().app_cache_dir()?.join("notifications");
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&directory)?;
        let icon = directory.join("sirinvpn.png");
        if fs::read(&icon).ok().as_deref() != Some(ICON) {
            let mut file = tempfile::NamedTempFile::new_in(&directory)?;
            file.write_all(ICON)?;
            file.persist(&icon)?;
        }
        // A persistent local asset also works from target/release and after an
        // AppImage unmounts; neither an installed icon theme nor a live mount is needed.
        let icon = tauri::Url::from_file_path(icon)
            .map_err(|_| anyhow::anyhow!("notification icon path is unavailable"))?;
        Notification::new()
            .appname("SirinVPN")
            .summary("SirinVPN")
            .body(body)
            .icon(icon.as_str())
            // Both generated Linux bundles use SirinVPN.desktop.
            .hint(Hint::DesktopEntry("SirinVPN".to_owned()))
            .show()?;
        Ok(())
    }
}
