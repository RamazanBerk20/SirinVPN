use serde::{Deserialize, Serialize};
use std::{io, io::Read, path::Path};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AppPreferences {
    pub start_on_login: bool,
    pub launch_minimized: bool,
    pub close_to_tray: bool,
    pub notifications: bool,
    pub animations: bool,
}

impl Default for AppPreferences {
    fn default() -> Self {
        Self {
            start_on_login: false,
            launch_minimized: false,
            close_to_tray: false,
            notifications: false,
            animations: true,
        }
    }
}

#[derive(Serialize, Deserialize)]
struct Document {
    schema_version: u16,
    preferences: AppPreferences,
}

pub fn read(path: &Path) -> io::Result<AppPreferences> {
    let file = match sirinvpn_platform::files::open_no_follow(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Ok(AppPreferences::default());
        }
        Err(error) => return Err(error),
    };
    let mut bytes = Vec::new();
    file.take(4097).read_to_end(&mut bytes)?;
    if bytes.len() > 4096 {
        return Err(io::Error::other("preferences exceed the size limit"));
    }
    let document: Document = serde_json::from_slice(&bytes)?;
    if document.schema_version != 1 {
        return Err(io::Error::other("unsupported preferences version"));
    }
    Ok(document.preferences)
}

pub fn write(path: &Path, preferences: &AppPreferences) -> io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::other("missing parent"))?;
    sirinvpn_platform::files::create_private_directory(parent)?;
    let document = Document {
        schema_version: 1,
        preferences: preferences.clone(),
    };
    sirinvpn_platform::files::atomic_write(path, &serde_json::to_vec_pretty(&document)?, true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sirinvpn_platform::files;
    use std::fs;

    #[test]
    fn first_launch_has_no_startup_or_background_side_effects() {
        let directory = tempfile::tempdir().unwrap();
        let preferences = read(&directory.path().join("missing.json")).unwrap();
        assert_eq!(preferences, AppPreferences::default());
        assert!(!preferences.start_on_login && !preferences.close_to_tray);
        assert!(!preferences.launch_minimized && !preferences.notifications);
    }

    #[test]
    fn preferences_survive_restart_and_remain_private() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("app/settings.json");
        let preferences = AppPreferences {
            close_to_tray: true,
            notifications: true,
            animations: false,
            ..AppPreferences::default()
        };
        write(&path, &preferences).unwrap();
        assert_eq!(read(&path).unwrap(), preferences);
        files::validate_private_file(&files::open_no_follow(&path).unwrap()).unwrap();
        write(&path, &AppPreferences::default()).unwrap();
        assert_eq!(read(&path).unwrap(), AppPreferences::default());
    }

    #[test]
    fn invalid_or_future_preferences_are_never_silently_replaced() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("settings.json");
        for bytes in [
            "broken".to_owned(),
            " ".repeat(4097),
            r#"{"schema_version":2,"preferences":{}}"#.to_owned(),
            r#"{"schema_version":1,"preferences":{"notifications":"yes"}}"#.to_owned(),
        ] {
            fs::write(&path, &bytes).unwrap();
            assert!(read(&path).is_err());
            assert_eq!(fs::read_to_string(&path).unwrap(), bytes);
        }
    }

    #[test]
    fn new_fields_get_safe_defaults() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("settings.json");
        fs::write(
            &path,
            r#"{"schema_version":1,"preferences":{"animations":false}}"#,
        )
        .unwrap();
        assert_eq!(
            read(&path).unwrap(),
            AppPreferences {
                animations: false,
                ..AppPreferences::default()
            }
        );
    }
}
