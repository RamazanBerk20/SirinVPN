//! Files for elevated update transactions: only SYSTEM and elevated machine
//! administrators can modify them, including when the caller has an ordinary SID.
use super::security::{self, SecurityDescriptor};
use std::{
    fs::{File, OpenOptions},
    io,
    os::windows::{ffi::OsStrExt, fs::OpenOptionsExt, io::FromRawHandle},
    path::Path,
    ptr,
};
use windows_sys::Win32::{
    Foundation::{ERROR_ALREADY_EXISTS, INVALID_HANDLE_VALUE},
    Storage::FileSystem::*,
};

pub fn create_directory(path: &Path) -> io::Result<()> {
    let name = security::wide_units(path.as_os_str().encode_wide().collect())?;
    let descriptor = SecurityDescriptor::from_sddl("O:BAG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")?;
    if unsafe { CreateDirectoryW(name.as_ptr(), &descriptor.attributes()) } == 0 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(ERROR_ALREADY_EXISTS as i32) {
            return Err(error);
        }
    }
    validate_directory(path)
}

pub fn validate_directory(path: &Path) -> io::Result<()> {
    super::files::validate_private_directory(path)?;
    let directory = OpenOptions::new()
        .access_mode(READ_CONTROL)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;
    security::require_system_managed(&directory)
}

pub fn validate_file(file: &File) -> io::Result<()> {
    super::files::validate_private_file(file)?;
    security::require_system_managed(file)
}

pub fn restrict_file(file: &File) -> io::Result<()> {
    // The file must inherit a safe ACL from its administrator-owned parent from
    // creation. Never adopt a file that ordinary users could already have open.
    validate_file(file)
}

pub fn open_lock(path: &Path) -> io::Result<File> {
    open(path, OPEN_ALWAYS)
}

pub fn create_file(path: &Path) -> io::Result<File> {
    open(path, CREATE_NEW)
}

fn open(path: &Path, disposition: FILE_CREATION_DISPOSITION) -> io::Result<File> {
    validate_directory(path.parent().ok_or(io::ErrorKind::InvalidInput)?)?;
    let name = security::wide_units(path.as_os_str().encode_wide().collect())?;
    let descriptor = SecurityDescriptor::from_sddl("O:BAG:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)")?;
    let raw = unsafe {
        CreateFileW(
            name.as_ptr(),
            FILE_GENERIC_READ | FILE_GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            &descriptor.attributes(),
            disposition,
            FILE_FLAG_OPEN_REPARSE_POINT,
            ptr::null_mut(),
        )
    };
    if raw == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    let file = unsafe { File::from_raw_handle(raw) };
    validate_file(&file)?;
    Ok(file)
}
