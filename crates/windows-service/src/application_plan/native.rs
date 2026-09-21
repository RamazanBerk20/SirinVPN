use super::*;
use sirinvpn_platform::windows::security;
use std::{io, path::Path, ptr};
use windows_sys::Win32::System::WindowsProgramming::DRIVE_FIXED;
use windows_sys::Win32::{
    Foundation::*, NetworkManagement::WindowsFilteringPlatform::*, Storage::FileSystem::*,
};

struct FileHandle(HANDLE);
impl Drop for FileHandle {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.0);
        }
    }
}
struct Blob(*mut FWP_BYTE_BLOB);
impl Drop for Blob {
    fn drop(&mut self) {
        unsafe {
            FwpmFreeMemory0((&mut self.0 as *mut *mut FWP_BYTE_BLOB).cast());
        }
    }
}

pub(crate) fn select(value: &str) -> Result<SelectedApplication, ServiceError> {
    require_path(value)?;
    select_inner(value).map_err(|_| ServiceError::InvalidApplication)
}
fn select_inner(value: &str) -> io::Result<SelectedApplication> {
    // Reject UNC/device/ADS syntax before any filesystem access by SYSTEM.
    let root = security::wide(&value[..3])?;
    if unsafe { GetDriveTypeW(root.as_ptr()) } != DRIVE_FIXED {
        return Err(invalid());
    }
    let mut ancestors = Path::new(value).ancestors().collect::<Vec<_>>();
    ancestors.reverse();
    let mut held = Vec::new();
    for (index, path) in ancestors.iter().enumerate() {
        let wide = security::wide(path.to_str().ok_or_else(invalid)?)?;
        let handle = unsafe {
            CreateFileW(
                wide.as_ptr(),
                FILE_READ_ATTRIBUTES,
                FILE_SHARE_READ,
                ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
                ptr::null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        let handle = FileHandle(handle);
        let mut info = BY_HANDLE_FILE_INFORMATION::default();
        if unsafe { GetFileInformationByHandle(handle.0, &mut info) } == 0
            || info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
            || (index + 1 == ancestors.len())
                != (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY == 0)
            || index + 1 == ancestors.len() && info.nNumberOfLinks != 1
        {
            return Err(invalid());
        }
        held.push(handle);
    }
    let wide = security::wide(value)?;
    let mut blob = ptr::null_mut();
    let code = unsafe { FwpmGetAppIdFromFileName0(wide.as_ptr(), &mut blob) };
    if code != 0 {
        return Err(io::Error::from_raw_os_error(code as i32));
    }
    let blob = Blob(blob);
    if blob.0.is_null() {
        return Err(invalid());
    }
    let found = unsafe { &*blob.0 };
    if found.data.is_null() || !(8..=32768).contains(&found.size) {
        return Err(invalid());
    }
    let selected = SelectedApplication {
        executable: value.to_owned(),
        app_id: unsafe { std::slice::from_raw_parts(found.data, found.size as usize) }.to_vec(),
    };
    if !selected.validate() {
        return Err(invalid());
    }
    Ok(selected)
}
fn invalid() -> io::Error {
    io::ErrorKind::InvalidInput.into()
}
