//! Private current state, bounded reads, and atomic file replacement.
use std::{
    fs::{File, OpenOptions},
    io::{self, Read, Write},
    path::Path,
};

#[cfg(any(unix, test))]
use std::fs;

pub fn create_private_directory(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(path)?;
        let metadata = fs::symlink_metadata(path)?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(unsafe_path());
        }
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
    }
    #[cfg(windows)]
    {
        crate::windows::files::create_private_directory(path)
    }
}

pub fn restrict_file(file: &File) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))
    }
    #[cfg(windows)]
    {
        crate::windows::files::restrict_file(file)
    }
}

/// Restrict a newly created, empty temporary directory before writing any data.
pub fn restrict_temporary_directory(directory: &tempfile::TempDir) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
    }
    #[cfg(windows)]
    {
        crate::windows::files::restrict_temporary_directory(directory)
    }
}

#[cfg(windows)]
pub fn rename_directory_noreplace(source: &Path, destination: &Path) -> io::Result<()> {
    crate::windows::files::rename_directory_noreplace(source, destination)
}

/// Validate existing state without repairing permissions or adopting its owner.
pub fn validate_private_directory(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let metadata = fs::symlink_metadata(path)?;
        if !metadata.is_dir()
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.mode() & 0o777 != 0o700
        {
            return Err(unsafe_path());
        }
        Ok(())
    }
    #[cfg(windows)]
    {
        crate::windows::files::validate_private_directory(path)
    }
}

pub fn validate_private_file(file: &File) -> io::Result<()> {
    regular_file(file)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let metadata = file.metadata()?;
        if metadata.uid() != unsafe { libc::geteuid() }
            || metadata.mode() & 0o777 != 0o600
            || metadata.nlink() != 1
        {
            return Err(unsafe_path());
        }
        Ok(())
    }
    #[cfg(windows)]
    {
        crate::windows::files::validate_private_file(file)
    }
}

pub fn open_no_follow(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    no_follow(&mut options);
    let file = options.open(path)?;
    regular_file(&file)?;
    Ok(file)
}

pub fn open_private_lock(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    no_follow(&mut options);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options.open(path)?;
    regular_file(&file)?;
    restrict_file(&file)?;
    Ok(file)
}

pub fn create_private_file(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create_new(true);
    no_follow(&mut options);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options.open(path)?;
    restrict_file(&file)?;
    Ok(file)
}

pub fn read_bounded(path: &Path, maximum: usize) -> io::Result<Vec<u8>> {
    let file = open_no_follow(path)?;
    if file.metadata()?.len() > maximum as u64 {
        return Err(unsafe_path());
    }
    let mut bytes = Vec::new();
    file.take((maximum as u64).saturating_add(1))
        .read_to_end(&mut bytes)?;
    if bytes.len() > maximum {
        return Err(unsafe_path());
    }
    Ok(bytes)
}

pub fn atomic_write(path: &Path, bytes: &[u8], replace: bool) -> io::Result<()> {
    let parent = path
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let mut temporary = tempfile::Builder::new()
        .prefix(".sirinvpn-")
        .tempfile_in(parent)?;
    restrict_file(temporary.as_file())?;
    temporary.write_all(bytes)?;
    persist(temporary, path, replace)?;
    Ok(())
}

pub fn persist(temporary: tempfile::NamedTempFile, path: &Path, replace: bool) -> io::Result<File> {
    temporary.as_file().sync_all()?;
    #[cfg(unix)]
    let file = if replace {
        temporary.persist(path)
    } else {
        temporary.persist_noclobber(path)
    }
    .map_err(|error| error.error)?;
    #[cfg(windows)]
    let file = crate::windows::files::persist(temporary, path, replace)?;
    file.sync_all()?;
    sync_directory(
        path.parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or(Path::new(".")),
    )?;
    Ok(file)
}

/// Unix syncs the directory entry. Windows replacement is write-through in
/// `persist`; this verifies the directory because Windows has no directory fsync.
pub fn sync_directory(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        File::open(path)?.sync_all()
    }
    #[cfg(windows)]
    {
        crate::windows::files::validate_directory(path)
    }
}

fn no_follow(options: &mut OpenOptions) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.custom_flags(windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT);
    }
}

fn regular_file(file: &File) -> io::Result<()> {
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(unsafe_path());
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes()
            & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT
            != 0
        {
            return Err(unsafe_path());
        }
    }
    Ok(())
}

fn unsafe_path() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "unsafe local state path")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replacements_are_atomic_and_new_exports_do_not_overwrite_existing_files() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state");
        atomic_write(&path, b"first", false).unwrap();
        assert!(atomic_write(&path, b"unconfirmed", false).is_err());
        assert_eq!(read_bounded(&path, 5).unwrap(), b"first");
        atomic_write(&path, b"current", true).unwrap();
        assert_eq!(read_bounded(&path, 7).unwrap(), b"current");
        assert!(read_bounded(&path, 6).is_err());
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn symlink_reads_and_locks_are_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("original");
        fs::write(&target, b"unchanged").unwrap();
        let link = dir.path().join("state");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(open_no_follow(&link).is_err());
        assert!(open_private_lock(&link).is_err());
        assert_eq!(fs::read(target).unwrap(), b"unchanged");
    }
}
