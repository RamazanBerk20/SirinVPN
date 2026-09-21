//! Freedesktop startup registration, with XDG paths and correctly quoted AppImage paths.
use std::{
    fs, io,
    io::{Read, Write},
    path::{Path, PathBuf},
};
use tauri::{AppHandle, Manager};

fn entry_path(app: &AppHandle) -> io::Result<PathBuf> {
    Ok(app
        .path()
        .config_dir()
        .map_err(io::Error::other)?
        .join("autostart")
        .join("org.sirinvpn.client.desktop"))
}

pub fn is_enabled(app: &AppHandle) -> io::Result<bool> {
    read_enabled(&entry_path(app)?)
}

pub fn set_enabled(app: &AppHandle, enabled: bool) -> io::Result<()> {
    let path = entry_path(app)?;
    if !enabled {
        return match fs::remove_file(path) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            result => result,
        };
    }
    // A mounted AppImage executable disappears after exit. Register its original file.
    let executable = app
        .env()
        .appimage
        .map(PathBuf::from)
        .unwrap_or(std::env::current_exe()?);
    write_entry(&path, &executable)
}

fn read_enabled(path: &Path) -> io::Result<bool> {
    let file = match fs::File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error),
    };
    let mut text = String::new();
    file.take(16385).read_to_string(&mut text)?;
    if text.len() > 16384 {
        return Err(io::Error::other("startup entry exceeds size limit"));
    }
    let mut in_entry = false;
    let mut executable = false;
    let mut application = false;
    let mut disabled = false;
    for line in text.lines().map(str::trim) {
        if line.starts_with('[') {
            in_entry = line == "[Desktop Entry]";
            continue;
        }
        if !in_entry {
            continue;
        }
        if let Some((key, value)) = line.split_once('=') {
            match (key.trim(), value.trim()) {
                ("Hidden", "true") | ("X-GNOME-Autostart-enabled", "false") => disabled = true,
                ("Exec", value) if !value.is_empty() => executable = true,
                ("Type", "Application") => application = true,
                _ => {}
            }
        }
    }
    Ok(application && executable && !disabled)
}

fn write_entry(path: &Path, executable: &Path) -> io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    let command = quote_executable(executable)?;
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::other("missing parent"))?;
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(parent)?;
    let mut temporary = tempfile::Builder::new()
        .prefix(".sirinvpn-startup-")
        .tempfile_in(parent)?;
    // GIO checks the executable before expanding literal percent escapes. A fixed
    // launcher lets AppImage paths containing '%' pass that check as an argument.
    write!(
        temporary,
        "[Desktop Entry]\nType=Application\nVersion=1.0\nName=SirinVPN\nExec=/usr/bin/env -- {command} --autostart\nTerminal=false\nStartupNotify=false\n"
    )?;
    temporary.as_file().sync_all()?;
    temporary.persist(path).map_err(|error| error.error)?;
    Ok(())
}

fn quote_executable(path: &Path) -> io::Result<String> {
    let value = path
        .to_str()
        .ok_or_else(|| io::Error::other("startup path is not UTF-8"))?;
    if !path.is_absolute() || value.chars().any(|ch| ch.is_control() || ch == '=') {
        return Err(io::Error::other("unsupported startup executable path"));
    }
    let mut quoted = String::from("\"");
    for ch in value.chars() {
        match ch {
            '\\' | '"' | '`' | '$' => {
                quoted.push('\\');
                quoted.push(ch);
            }
            '%' => quoted.push_str("%%"),
            _ => quoted.push(ch),
        }
    }
    quoted.push('"');
    // The desktop-entry string layer is decoded before Exec argument quoting.
    Ok(quoted.replace('\\', "\\\\"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spaces_and_shell_characters_stay_in_one_literal_executable() {
        assert_eq!(
            quote_executable(Path::new("/home/user/My VPN.AppImage")).unwrap(),
            "\"/home/user/My VPN.AppImage\""
        );
        assert_eq!(
            quote_executable(Path::new("/tmp/$file`name`%f\\\";echo.AppImage")).unwrap(),
            r#""/tmp/\\$file\\`name\\`%%f\\\\\\";echo.AppImage""#
        );
        assert!(quote_executable(Path::new("/tmp/file\nExec=evil")).is_err());
        assert!(quote_executable(Path::new("relative.AppImage")).is_err());
    }

    #[test]
    fn system_disabled_entries_are_reported_as_disabled() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory
            .path()
            .join("autostart/org.sirinvpn.client.desktop");
        assert!(!read_enabled(&path).unwrap());
        write_entry(&path, Path::new("/usr/bin/sirinvpn-desktop")).unwrap();
        assert!(read_enabled(&path).unwrap());
        fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(b"Hidden=true\n")
            .unwrap();
        assert!(!read_enabled(&path).unwrap());
        write_entry(&path, Path::new("/usr/bin/sirinvpn-desktop")).unwrap();
        assert!(read_enabled(&path).unwrap());
        fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(b"X-GNOME-Autostart-enabled=false\n")
            .unwrap();
        assert!(!read_enabled(&path).unwrap());
    }

    #[test]
    fn invalid_replacement_does_not_destroy_an_existing_registration() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("startup.desktop");
        write_entry(&path, Path::new("/opt/SirinVPN.AppImage")).unwrap();
        let original = fs::read(&path).unwrap();
        assert!(write_entry(&path, Path::new("/tmp/bad\nfile")).is_err());
        assert_eq!(fs::read(&path).unwrap(), original);
    }
}
