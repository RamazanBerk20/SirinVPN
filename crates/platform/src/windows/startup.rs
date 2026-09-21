//! User logon registration, independent of the machine VPN service's boot policy.
use super::security;
use std::{io, path::Path, ptr};
use windows_sys::Win32::{
    Foundation::{ERROR_FILE_NOT_FOUND, ERROR_SUCCESS},
    System::Registry::*,
};

const RUN: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
const APPROVED: &str = r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run";
const NAME: &str = "SirinVPN";
struct Key(HKEY);
impl Drop for Key {
    fn drop(&mut self) {
        unsafe {
            RegCloseKey(self.0);
        }
    }
}

pub fn is_enabled(executable: &Path) -> io::Result<bool> {
    let expected = command(executable)?;
    let Some((kind, bytes)) = read_value(RUN)? else {
        return Ok(false);
    };
    if kind != REG_SZ || bytes.len() != expected.len() * 2 {
        return Ok(false);
    }
    if !expected
        .iter()
        .zip(bytes.chunks_exact(2))
        .all(|(a, b)| *a == u16::from_le_bytes([b[0], b[1]]))
    {
        return Ok(false);
    }
    // Read only our entry. Windows can independently disable an existing Run
    // registration; unknown approval states are never reported as enabled.
    Ok(match read_value(APPROVED)? {
        None => true,
        Some((REG_BINARY, bytes)) if bytes.len() == 12 => matches!(bytes[0], 2 | 6),
        _ => false,
    })
}

pub fn set_enabled(executable: &Path, enabled: bool) -> io::Result<()> {
    let command = command(executable)?;
    let path = security::wide(RUN)?;
    let name = security::wide(NAME)?;
    let mut raw = ptr::null_mut();
    check(unsafe {
        RegCreateKeyExW(
            HKEY_CURRENT_USER,
            path.as_ptr(),
            0,
            ptr::null(),
            REG_OPTION_NON_VOLATILE,
            KEY_SET_VALUE,
            ptr::null(),
            &mut raw,
            ptr::null_mut(),
        )
    })?;
    let key = Key(raw);
    if enabled {
        check(unsafe {
            RegSetValueExW(
                key.0,
                name.as_ptr(),
                0,
                REG_SZ,
                command.as_ptr().cast(),
                (command.len() * 2) as u32,
            )
        })?;
        if !is_enabled(executable)? {
            return Err(io::Error::other(
                "Enable SirinVPN in Windows Settings > Apps > Startup.",
            ));
        }
    } else {
        let code = unsafe { RegDeleteValueW(key.0, name.as_ptr()) };
        if code != ERROR_FILE_NOT_FOUND {
            check(code)?;
        }
    }
    Ok(())
}

fn command(path: &Path) -> io::Result<Vec<u16>> {
    let value = path
        .to_str()
        .ok_or_else(|| io::Error::other("invalid startup executable"))?;
    if !path.is_absolute() || value.chars().any(|c| c.is_control() || c == '"') {
        return Err(io::Error::other("invalid startup executable"));
    }
    let command = security::wide(&format!("\"{value}\" --autostart"))?;
    if command.len() > 261 {
        return Err(io::Error::other("the startup executable path is too long"));
    }
    Ok(command)
}

fn read_value(path: &str) -> io::Result<Option<(u32, Vec<u8>)>> {
    let path = security::wide(path)?;
    let name = security::wide(NAME)?;
    let mut raw = ptr::null_mut();
    let code = unsafe {
        RegOpenKeyExW(
            HKEY_CURRENT_USER,
            path.as_ptr(),
            0,
            KEY_QUERY_VALUE,
            &mut raw,
        )
    };
    if code == ERROR_FILE_NOT_FOUND {
        return Ok(None);
    }
    check(code)?;
    let key = Key(raw);
    let mut bytes = vec![0u8; 4096];
    let mut size = bytes.len() as u32;
    let mut kind = 0;
    let code = unsafe {
        RegQueryValueExW(
            key.0,
            name.as_ptr(),
            ptr::null(),
            &mut kind,
            bytes.as_mut_ptr(),
            &mut size,
        )
    };
    if code == ERROR_FILE_NOT_FOUND {
        return Ok(None);
    }
    check(code)?;
    if size > bytes.len() as u32 {
        return Err(io::Error::other("invalid startup registration"));
    }
    bytes.truncate(size as usize);
    Ok(Some((kind, bytes)))
}
fn check(code: u32) -> io::Result<()> {
    if code == ERROR_SUCCESS {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(code as i32))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn startup_command_keeps_spaces_literal_and_rejects_argument_injection() {
        let value = command(Path::new(r"C:\Program Files\SirinVPN\sirinvpn-desktop.exe")).unwrap();
        assert_eq!(
            String::from_utf16(&value[..value.len() - 1]).unwrap(),
            r#""C:\Program Files\SirinVPN\sirinvpn-desktop.exe" --autostart"#
        );
        assert!(command(Path::new("C:\\bad\" --other.exe")).is_err());
        assert!(command(Path::new("relative.exe")).is_err());
    }
}
