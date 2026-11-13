//! Files and programs reach native code only through a dialog this process showed.
//!
//! `pick_path` opens the native chooser in Rust and returns the chosen path, which the
//! WebView displays and passes back to name that choice. A command accepts the path only
//! while this process holds a grant for it and for that command's purpose, so a script in
//! the WebView can't make native code read, write or run a path the person never chose.
use serde::Deserialize;
use std::{
    path::PathBuf,
    sync::{Mutex, PoisonError},
    time::{Duration, Instant},
};
use tauri_plugin_dialog::DialogExt;

/// A grant stays valid this long after it was chosen or last used.
const LIFETIME: Duration = Duration::from_secs(60 * 60);
const MAX_GRANTS: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Purpose {
    Program,
    BackupExport,
    BackupImport,
    VpsBackupExport,
    VpsBackupRestore,
    VpsBackupFolder,
    SshKey,
    RecoveryExport,
    RecoveryImport,
    WireguardExport,
}

enum Kind {
    Open,
    Save,
    Folder,
}

impl Purpose {
    fn kind(self) -> Kind {
        match self {
            Self::BackupExport
            | Self::VpsBackupExport
            | Self::RecoveryExport
            | Self::WireguardExport => Kind::Save,
            Self::VpsBackupFolder => Kind::Folder,
            Self::Program
            | Self::BackupImport
            | Self::VpsBackupRestore
            | Self::SshKey
            | Self::RecoveryImport => Kind::Open,
        }
    }
}

/// Cosmetic options from the WebView; they never decide what is granted.
#[derive(Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub(crate) struct PickOptions {
    title: Option<String>,
    default_path: Option<String>,
    filters: Vec<Filter>,
}

#[derive(Deserialize)]
struct Filter {
    name: String,
    extensions: Vec<String>,
}

struct Grant {
    purpose: Purpose,
    path: String,
    expires: Instant,
}

#[derive(Default)]
struct Grants(Vec<Grant>);

impl Grants {
    fn add(&mut self, purpose: Purpose, path: String, now: Instant) {
        self.0.retain(|grant| {
            grant.expires > now && !(grant.purpose == purpose && grant.path == path)
        });
        if self.0.len() >= MAX_GRANTS {
            self.0.remove(0);
        }
        self.0.push(Grant {
            purpose,
            path,
            expires: now + LIFETIME,
        });
    }

    fn check(&mut self, purpose: Purpose, path: &str, now: Instant) -> Result<PathBuf, String> {
        self.0.retain(|grant| grant.expires > now);
        let grant = self
            .0
            .iter_mut()
            .find(|grant| grant.purpose == purpose && grant.path == path)
            .ok_or_else(|| "Choose it again with Browse. SirinVPN only uses files and programs chosen in its own file chooser in the last hour.".to_owned())?;
        // A program grant lets the WebView launch it, so it ends an hour after the pick, not after the last use.
        if purpose != Purpose::Program {
            grant.expires = now + LIFETIME;
        }
        Ok(PathBuf::from(&grant.path))
    }

    fn remove(&mut self, purpose: Purpose, path: &str) {
        self.0
            .retain(|grant| !(grant.purpose == purpose && grant.path == path));
    }
}

static GRANTS: Mutex<Grants> = Mutex::new(Grants(Vec::new()));

/// The path, if the person chose it for `purpose` through `pick_path`.
pub(crate) fn granted(purpose: Purpose, path: &str) -> Result<PathBuf, String> {
    GRANTS
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .check(purpose, path, Instant::now())
}

/// Ends a save grant once used, so a later call can't silently write there again.
pub(crate) fn release(purpose: Purpose, path: &str) {
    GRANTS
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .remove(purpose, path);
}

/// `~/.ssh`, which file choosers hide by default.
fn ssh_directory() -> Option<PathBuf> {
    let home = std::env::var_os(if cfg!(windows) { "USERPROFILE" } else { "HOME" })?;
    Some(PathBuf::from(home).join(".ssh")).filter(|path| path.is_dir())
}

#[tauri::command]
pub(crate) async fn pick_path(
    window: tauri::WebviewWindow,
    purpose: Purpose,
    options: Option<PickOptions>,
) -> Result<Option<String>, String> {
    let options = options.unwrap_or_default();
    let mut dialog = window.dialog().file().set_parent(&window);
    if let Some(title) = options.title {
        dialog = dialog.set_title(title);
    }
    for filter in &options.filters {
        let extensions: Vec<&str> = filter.extensions.iter().map(String::as_str).collect();
        dialog = dialog.add_filter(&filter.name, &extensions);
    }
    let start = options
        .default_path
        .map(PathBuf::from)
        .or_else(|| (purpose == Purpose::SshKey).then(ssh_directory).flatten());
    if let Some(start) = start {
        if start.is_dir() {
            dialog = dialog.set_directory(start);
        } else {
            if let Some(parent) = start.parent().filter(|parent| parent.is_dir()) {
                dialog = dialog.set_directory(parent);
            }
            if let Some(name) = start.file_name() {
                dialog = dialog.set_file_name(name.to_string_lossy());
            }
        }
    }
    // The save chooser asks before replacing an existing file.
    let picked = tauri::async_runtime::spawn_blocking(move || match purpose.kind() {
        Kind::Open => dialog.blocking_pick_file(),
        Kind::Save => dialog.blocking_save_file(),
        Kind::Folder => dialog.blocking_pick_folder(),
    })
    .await
    .map_err(|_| "The file chooser was interrupted.".to_owned())?;
    let Some(picked) = picked else {
        return Ok(None);
    };
    let path = picked
        .into_path()
        .map_err(|_| "Choose a file on this device.".to_owned())?
        .into_os_string()
        .into_string()
        .map_err(|_| "Choose a file whose folder and name use readable characters.".to_owned())?;
    GRANTS.lock().unwrap_or_else(PoisonError::into_inner).add(
        purpose,
        path.clone(),
        Instant::now(),
    );
    Ok(Some(path))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_chosen_paths_for_the_same_purpose_are_accepted() {
        let mut grants = Grants::default();
        let now = Instant::now();
        assert!(grants.check(Purpose::Program, "/bin/sh", now).is_err());
        grants.add(Purpose::BackupImport, "/home/me/a.sirin".into(), now);
        assert_eq!(
            grants
                .check(Purpose::BackupImport, "/home/me/a.sirin", now)
                .unwrap(),
            PathBuf::from("/home/me/a.sirin")
        );
        assert!(
            grants
                .check(Purpose::SshKey, "/home/me/a.sirin", now)
                .is_err()
        );
        assert!(
            grants
                .check(Purpose::BackupImport, "/home/me/a.sirin/", now)
                .is_err()
        );
        assert!(
            grants
                .check(Purpose::BackupImport, "/home/me/../me/a.sirin", now)
                .is_err()
        );
    }

    #[test]
    fn grants_expire_unless_used_and_end_when_released() {
        let mut grants = Grants::default();
        let now = Instant::now();
        grants.add(Purpose::SshKey, "/home/me/.ssh/id".into(), now);
        let later = now + LIFETIME - Duration::from_secs(1);
        assert!(
            grants
                .check(Purpose::SshKey, "/home/me/.ssh/id", later)
                .is_ok()
        );
        assert!(
            grants
                .check(
                    Purpose::SshKey,
                    "/home/me/.ssh/id",
                    later + LIFETIME - Duration::from_secs(1)
                )
                .is_ok()
        );
        assert!(
            grants
                .check(Purpose::SshKey, "/home/me/.ssh/id", later + LIFETIME * 3)
                .is_err()
        );
        grants.add(Purpose::BackupExport, "/home/me/b.sirin".into(), now);
        grants.remove(Purpose::BackupExport, "/home/me/b.sirin");
        assert!(
            grants
                .check(Purpose::BackupExport, "/home/me/b.sirin", now)
                .is_err()
        );
    }

    #[test]
    fn program_grants_end_an_hour_after_the_pick_however_often_used() {
        let mut grants = Grants::default();
        let now = Instant::now();
        grants.add(Purpose::Program, "/usr/bin/firefox".into(), now);
        let later = now + LIFETIME - Duration::from_secs(1);
        assert!(
            grants
                .check(Purpose::Program, "/usr/bin/firefox", later)
                .is_ok()
        );
        assert!(
            grants
                .check(Purpose::Program, "/usr/bin/firefox", now + LIFETIME)
                .is_err()
        );
    }

    #[test]
    fn grants_are_bounded() {
        let mut grants = Grants::default();
        let now = Instant::now();
        for n in 0..=MAX_GRANTS {
            grants.add(Purpose::BackupImport, format!("/f{n}"), now);
        }
        assert_eq!(grants.0.len(), MAX_GRANTS);
        assert!(grants.check(Purpose::BackupImport, "/f0", now).is_err());
        assert!(
            grants
                .check(Purpose::BackupImport, &format!("/f{MAX_GRANTS}"), now)
                .is_ok()
        );
    }
}
