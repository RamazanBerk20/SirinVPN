use super::*;
use sirinvpn_platform::{
    files,
    windows::{
        dpapi::{self, Scope},
        security::{self, SYSTEM_SID, SecurityDescriptor},
    },
};
use std::{
    fs::{self, File},
    io::{self, Read},
    os::windows::ffi::OsStringExt,
    path::PathBuf,
    ptr,
};
use windows_sys::Win32::{
    Foundation::{ERROR_FILE_NOT_FOUND, ERROR_SUCCESS},
    System::{Com::CoTaskMemFree, Registry::*},
    UI::Shell::{FOLDERID_ProgramData, KF_FLAG_DEFAULT, SHGetKnownFolderPath},
};
use zeroize::Zeroizing;

const MAX_STATE: usize = 512 * 1024;
const BINDING: &str = "windows-service-current-session:1";

pub(crate) struct SessionStore {
    path: PathBuf,
    _lock: File,
}

impl SessionStore {
    pub(crate) fn open() -> io::Result<Self> {
        if security::current_user_sid()? != SYSTEM_SID {
            return Err(invalid());
        }
        let directory = state_directory()?;
        files::create_private_directory(directory.parent().ok_or_else(invalid)?)?;
        files::create_private_directory(&directory)?;
        let lock = files::open_private_lock(&directory.join("operation.lock"))?;
        fs2::FileExt::try_lock_exclusive(&lock)?;
        Ok(Self {
            path: directory.join("session.dpapi"),
            _lock: lock,
        })
    }

    pub(crate) fn load(&self) -> io::Result<Option<SavedConnection>> {
        let file = match files::open_no_follow(&self.path) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        };
        security::require_private(&file)?;
        let mut encrypted = Vec::new();
        file.take((MAX_STATE + 16385) as u64)
            .read_to_end(&mut encrypted)?;
        if encrypted.len() > MAX_STATE + 16384 {
            return Err(invalid());
        }
        let bytes = dpapi::unprotect(&encrypted, Scope::Machine, BINDING)?;
        if bytes.len() > MAX_STATE {
            return Err(invalid());
        }
        let saved: SavedConnection = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
        saved.validate().map_err(|_| invalid())?;
        Ok(Some(saved))
    }

    pub(crate) fn save(&self, saved: &SavedConnection) -> io::Result<()> {
        saved.validate().map_err(|_| invalid())?;
        let bytes = Zeroizing::new(serde_json::to_vec(saved).map_err(|_| invalid())?);
        if bytes.len() > MAX_STATE {
            return Err(invalid());
        }
        let encrypted = dpapi::protect(&bytes, Scope::Machine, BINDING)?;
        files::atomic_write(&self.path, &encrypted, true)
    }

    pub(crate) fn remove(&self) -> io::Result<()> {
        match fs::remove_file(&self.path) {
            Ok(()) => files::sync_directory(self.path.parent().ok_or_else(invalid)?),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error),
        }
    }

    /// Administrator-requested uninstall may discard an undecodable current
    /// record, but only after proving that its path still names a private file.
    /// Its contents never authorize deleting routes when decoding has failed.
    pub(crate) fn validate_unreadable_removal(&self) -> io::Result<()> {
        let file = files::open_no_follow(&self.path)?;
        files::validate_private_file(&file)
    }

    pub(crate) fn remove_installation(self) -> io::Result<()> {
        self.remove()?;
        let directory = self.path.parent().ok_or_else(invalid)?.to_path_buf();
        drop(self);
        match fs::remove_file(directory.join("operation.lock")) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        fs::remove_dir(&directory)?;
        if let Some(parent) = directory.parent() {
            match fs::remove_dir(parent) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::DirectoryNotEmpty => {}
                Err(error) => return Err(error),
            }
        }
        let runtime = security::wide(r"SOFTWARE\SirinVPN\Runtime")?;
        let code = unsafe { RegDeleteKeyW(HKEY_LOCAL_MACHINE, runtime.as_ptr()) };
        if code != ERROR_FILE_NOT_FOUND {
            check(code)?;
        }
        Ok(())
    }

    /// A volatile registry value lives until reboot. It distinguishes service
    /// recovery from startup without relying on wall-clock time or writing a history.
    pub(crate) fn boot_nonce(&self) -> io::Result<uuid::Uuid> {
        let sd = SecurityDescriptor::from_sddl("O:SYG:SYD:P(A;CI;KA;;;SY)(A;CI;KA;;;BA)")?;
        let attributes = sd.attributes();
        let parent = security::wide(r"SOFTWARE\SirinVPN")?;
        let mut key = ptr::null_mut();
        check(unsafe {
            RegCreateKeyExW(
                HKEY_LOCAL_MACHINE,
                parent.as_ptr(),
                0,
                ptr::null(),
                REG_OPTION_NON_VOLATILE,
                KEY_CREATE_SUB_KEY,
                &attributes,
                &mut key,
                ptr::null_mut(),
            )
        })?;
        let parent = RegistryKey(key);
        let child = security::wide("Runtime")?;
        check(unsafe {
            RegCreateKeyExW(
                parent.0,
                child.as_ptr(),
                0,
                ptr::null(),
                REG_OPTION_VOLATILE,
                KEY_QUERY_VALUE | KEY_SET_VALUE,
                &attributes,
                &mut key,
                ptr::null_mut(),
            )
        })?;
        let key = RegistryKey(key);
        let name = security::wide("BootNonce")?;
        let mut bytes = [0u8; 16];
        let mut kind = 0;
        let mut size = bytes.len() as u32;
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
        if code == ERROR_SUCCESS {
            if kind != REG_BINARY || size != 16 {
                return Err(invalid());
            }
            let nonce = uuid::Uuid::from_bytes(bytes);
            if nonce.is_nil() {
                return Err(invalid());
            }
            return Ok(nonce);
        }
        if code != ERROR_FILE_NOT_FOUND {
            return Err(io::Error::from_raw_os_error(code as i32));
        }
        let nonce = uuid::Uuid::new_v4();
        check(unsafe {
            RegSetValueExW(
                key.0,
                name.as_ptr(),
                0,
                REG_BINARY,
                nonce.as_bytes().as_ptr(),
                16,
            )
        })?;
        Ok(nonce)
    }
}

pub(crate) fn state_directory() -> io::Result<PathBuf> {
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
    let path = unsafe { std::ffi::OsString::from_wide(std::slice::from_raw_parts(path, length)) };
    Ok(PathBuf::from(path).join("SirinVPN").join("Service"))
}

struct RegistryKey(HKEY);
impl Drop for RegistryKey {
    fn drop(&mut self) {
        unsafe {
            RegCloseKey(self.0);
        }
    }
}
fn check(code: u32) -> io::Result<()> {
    if code == 0 {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(code as i32))
    }
}
fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "Windows service state is unavailable or invalid",
    )
}
