use super::*;
use std::{ffi::OsString, os::windows::ffi::OsStringExt, ptr};
use windows_sys::Win32::{
    Foundation::{CloseHandle, WAIT_OBJECT_0, WAIT_TIMEOUT},
    System::{
        Com::CoTaskMemFree,
        Threading::{GetExitCodeProcess, WaitForSingleObject},
    },
    UI::Shell::{
        FOLDERID_ProgramData, KF_FLAG_DEFAULT, SEE_MASK_NOASYNC, SEE_MASK_NOCLOSEPROCESS,
        SHELLEXECUTEINFOW, SHGetKnownFolderPath, ShellExecuteExW,
    },
};

pub fn coordinator_available() -> io::Result<PathBuf> {
    let executable = std::env::current_exe()?;
    let coordinator = executable
        .parent()
        .ok_or_else(invalid)?
        .join("sirinvpn-windows-service.exe");
    let _protected = open_protected_program(&coordinator)?;
    Ok(coordinator)
}

/// Wait only for verified staging to complete. The independent administrator
/// worker retains the installer and recovery state after the desktop exits.
pub fn launch(bundle: &Path, manifest_sha256: &str, rollback: bool) -> io::Result<()> {
    if !bundle.is_absolute() || !valid_digest(manifest_sha256) {
        return Err(invalid());
    }
    let coordinator = coordinator_available()?;
    let _protected = open_protected_program(&coordinator)?;
    let file = security::wide(coordinator.to_str().ok_or_else(invalid)?)?;
    let verb = security::wide("runas")?;
    let argument = quote(bundle.to_str().ok_or_else(invalid)?)?;
    let command = if rollback {
        "--stage-rollback"
    } else {
        "--stage-update"
    };
    let arguments = security::wide(&format!("{command} {argument} {manifest_sha256}"))?;
    let mut execution = SHELLEXECUTEINFOW {
        cbSize: size_of::<SHELLEXECUTEINFOW>() as u32,
        fMask: SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC,
        lpVerb: verb.as_ptr(),
        lpFile: file.as_ptr(),
        lpParameters: arguments.as_ptr(),
        nShow: 1,
        ..Default::default()
    };
    if unsafe { ShellExecuteExW(&mut execution) } == 0 {
        return Err(io::Error::last_os_error());
    }
    drop(_protected);
    if execution.hProcess.is_null() {
        return Err(invalid());
    }
    struct Process(windows_sys::Win32::Foundation::HANDLE);
    impl Drop for Process {
        fn drop(&mut self) {
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
    let process = Process(execution.hProcess);
    let waited = unsafe { WaitForSingleObject(process.0, 120_000) };
    if waited == WAIT_TIMEOUT {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "Windows is still staging the update. Keep this window open and retry its status.",
        ));
    }
    if waited != WAIT_OBJECT_0 {
        return Err(io::Error::last_os_error());
    }
    let mut code = 1;
    if unsafe { GetExitCodeProcess(process.0, &mut code) } == 0 {
        return Err(io::Error::last_os_error());
    }
    if code != 0 {
        return Err(invalid());
    }
    Ok(())
}

pub(super) fn machine_directory() -> io::Result<PathBuf> {
    let mut path = ptr::null_mut();
    let code = unsafe {
        SHGetKnownFolderPath(
            &FOLDERID_ProgramData,
            KF_FLAG_DEFAULT as u32,
            ptr::null_mut(),
            &mut path,
        )
    };
    if code < 0 {
        return Err(io::Error::from_raw_os_error(code));
    }
    struct Memory(*mut u16);
    impl Drop for Memory {
        fn drop(&mut self) {
            unsafe {
                CoTaskMemFree(self.0.cast());
            }
        }
    }
    let _memory = Memory(path);
    if path.is_null() {
        return Err(invalid());
    }
    let mut length = 0;
    while length < 32767 && unsafe { *path.add(length) } != 0 {
        length += 1;
    }
    if length == 32767 {
        return Err(invalid());
    }
    let path = unsafe { OsString::from_wide(std::slice::from_raw_parts(path, length)) };
    Ok(PathBuf::from(path).join("SirinVPNUpdates"))
}

pub(super) fn install_directory_argument(path: &Path) -> io::Result<String> {
    let value = path.to_str().ok_or_else(invalid)?;
    if !path.is_absolute() || value.chars().any(|c| c.is_control() || c == '"') {
        return Err(invalid());
    }
    // NSIS requires /D= as the final, unquoted argument, even with spaces. This
    // goes directly to CreateProcess through raw_arg; no shell parses the path.
    Ok(format!("/D={value}"))
}

fn quote(value: &str) -> io::Result<String> {
    if value.chars().any(char::is_control) || value.len() > 32700 {
        return Err(invalid());
    }
    let mut output = String::from("\"");
    let mut slashes = 0;
    for c in value.chars() {
        if c == '\\' {
            slashes += 1;
            continue;
        }
        output.extend(std::iter::repeat_n(
            '\\',
            if c == '"' { slashes * 2 + 1 } else { slashes },
        ));
        slashes = 0;
        output.push(c);
    }
    output.extend(std::iter::repeat_n('\\', slashes * 2));
    output.push('"');
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn elevation_quotes_arguments_and_nsis_directory_stays_last_and_literal() {
        assert_eq!(quote(r"C:\A B\bundle").unwrap(), r#""C:\A B\bundle""#);
        assert_eq!(quote("C:\\A B\\").unwrap(), "\"C:\\A B\\\\\"");
        assert_eq!(
            install_directory_argument(Path::new(r"C:\Program Files\SirinVPN")).unwrap(),
            r"/D=C:\Program Files\SirinVPN"
        );
        assert!(install_directory_argument(Path::new("C:\\bad\" /S")).is_err());
    }
}
