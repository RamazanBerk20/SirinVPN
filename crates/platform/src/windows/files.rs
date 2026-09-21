use super::security::{self, SecurityDescriptor};
use std::{
    fs::{File, OpenOptions},
    io,
    os::windows::{
        ffi::OsStrExt,
        fs::{MetadataExt, OpenOptionsExt},
        io::{AsRawHandle, FromRawHandle},
    },
    path::Path,
};
use windows_sys::Win32::{
    Foundation::{ERROR_ALREADY_EXISTS, INVALID_HANDLE_VALUE},
    Storage::FileSystem::*,
};

fn path_wide(path: &Path) -> io::Result<Vec<u16>> {
    security::wide_units(path.as_os_str().encode_wide().collect())
}

/// Retain read handles without write/delete sharing across verification and DLL
/// loading. All non-root parent directories must also be protected from replacement.
pub struct ProtectedProgramFile {
    _file: File,
    _parents: Vec<File>,
}

pub fn open_protected_program(path: &Path) -> io::Result<ProtectedProgramFile> {
    if !path.is_absolute() {
        return Err(invalid());
    }
    let file = OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(invalid());
    }
    security::require_system_managed(&file)?;
    let mut parents = Vec::new();
    for parent in path
        .ancestors()
        .skip(1)
        .filter(|parent| parent.parent().is_some())
    {
        let directory = OpenOptions::new()
            .access_mode(READ_CONTROL)
            .share_mode(FILE_SHARE_READ)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(parent)?;
        let metadata = directory.metadata()?;
        if !metadata.is_dir() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(invalid());
        }
        security::require_system_managed_ancestor(&directory)?;
        parents.push(directory);
    }
    Ok(ProtectedProgramFile {
        _file: file,
        _parents: parents,
    })
}

pub fn create_program_directory(path: &Path) -> io::Result<()> {
    let descriptor = SecurityDescriptor::from_sddl(
        "O:BAG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;GRGX;;;BU)",
    )?;
    let name = path_wide(path)?;
    if unsafe { CreateDirectoryW(name.as_ptr(), &descriptor.attributes()) } == 0 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(ERROR_ALREADY_EXISTS as i32) {
            return Err(error);
        }
    }
    let directory = open_directory(path, false)?;
    security::require_system_managed(&directory)?;
    for parent in path
        .ancestors()
        .skip(1)
        .filter(|path| path.parent().is_some())
    {
        security::require_system_managed_ancestor(&open_directory(parent, false)?)?;
    }
    Ok(())
}

pub(crate) fn create_private_directory(path: &Path) -> io::Result<()> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        && !parent.try_exists()?
    {
        create_private_directory(parent)?;
    }
    let descriptor = SecurityDescriptor::private_for_current_user()?;
    let name = path_wide(path)?;
    if unsafe { CreateDirectoryW(name.as_ptr(), &descriptor.attributes()) } == 0 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(ERROR_ALREADY_EXISTS as i32) {
            return Err(error);
        }
    }
    let directory = open_directory(path, true)?;
    // An existing public directory must never be silently adopted as service state.
    security::require_private(&directory)?;
    security::restrict(&directory)
}

pub(crate) fn restrict_file(file: &File) -> io::Result<()> {
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(invalid());
    }
    let mut information: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut information) } == 0 {
        return Err(io::Error::last_os_error());
    }
    if information.nNumberOfLinks != 1 {
        return Err(invalid());
    }
    let raw = unsafe {
        ReOpenFile(
            file.as_raw_handle(),
            READ_CONTROL | WRITE_DAC,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            FILE_FLAG_OPEN_REPARSE_POINT,
        )
    };
    if raw == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    let reopened = unsafe { File::from_raw_handle(raw) };
    security::restrict(&reopened)
}

fn open_directory(path: &Path, writable_acl: bool) -> io::Result<File> {
    let directory = OpenOptions::new()
        .access_mode(READ_CONTROL | if writable_acl { WRITE_DAC } else { 0 })
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;
    let metadata = directory.metadata()?;
    if !metadata.is_dir() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(invalid());
    }
    Ok(directory)
}

pub(crate) fn validate_directory(path: &Path) -> io::Result<()> {
    open_directory(path, false).map(|_| ())
}

pub(crate) fn restrict_temporary_directory(directory: &tempfile::TempDir) -> io::Result<()> {
    security::restrict(&open_directory(directory.path(), true)?)
}

pub(crate) fn rename_directory_noreplace(source: &Path, destination: &Path) -> io::Result<()> {
    validate_private_directory(source)?;
    validate_directory(destination.parent().ok_or_else(invalid)?)?;
    let source = path_wide(source)?;
    let destination = path_wide(destination)?;
    // Omitting REPLACE_EXISTING and COPY_ALLOWED makes this a same-volume,
    // non-clobbering rename. The filesystem operation owns the existence check.
    if unsafe {
        MoveFileExW(
            source.as_ptr(),
            destination.as_ptr(),
            MOVEFILE_WRITE_THROUGH,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

pub(crate) fn validate_private_directory(path: &Path) -> io::Result<()> {
    security::require_private(&open_directory(path, false)?)
}

pub(crate) fn validate_private_file(file: &File) -> io::Result<()> {
    let mut information = BY_HANDLE_FILE_INFORMATION::default();
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut information) } == 0 {
        return Err(io::Error::last_os_error());
    }
    if information.nNumberOfLinks != 1
        || information.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
    {
        return Err(invalid());
    }
    security::require_private(file)
}

pub(crate) fn persist(
    temporary: tempfile::NamedTempFile,
    destination: &Path,
    replace: bool,
) -> io::Result<File> {
    let (file, path) = temporary.into_parts();
    let source = path_wide(&path)?;
    let destination = path_wide(destination)?;
    if unsafe { SetFileAttributesW(source.as_ptr(), FILE_ATTRIBUTE_NORMAL) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let flags = MOVEFILE_WRITE_THROUGH
        | if replace {
            MOVEFILE_REPLACE_EXISTING
        } else {
            0
        };
    // No cross-volume copy/delete fallback: the temporary is in the destination directory.
    if unsafe { MoveFileExW(source.as_ptr(), destination.as_ptr(), flags) } == 0 {
        return Err(io::Error::last_os_error());
    }
    drop(path);
    Ok(file)
}

fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "Windows state path is not an ordinary private file or directory",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    #[test]
    fn private_state_has_a_restricted_dacl_after_replacement() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("private");
        create_private_directory(&path).unwrap();
        let file = path.join("identity");
        crate::files::atomic_write(&file, b"encrypted only", false).unwrap();
        security::require_private(&File::open(file).unwrap()).unwrap();
    }

    #[test]
    fn hardlinked_state_cannot_be_restricted_or_overwritten_as_a_lock() {
        let directory = tempfile::tempdir().unwrap();
        let original = directory.path().join("original");
        fs::write(&original, b"unchanged").unwrap();
        let link = directory.path().join("lock");
        fs::hard_link(&original, &link).unwrap();
        assert!(crate::files::open_private_lock(&link).is_err());
        assert_eq!(fs::read(original).unwrap(), b"unchanged");
    }
}
