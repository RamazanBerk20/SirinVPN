use super::*;

impl InstalledReleaseStore {
    /// An elevated Windows updater must not grant the unelevated caller's SID
    /// write access to machine receipts, trusted keys, or cached executables.
    #[cfg(windows)]
    pub fn windows_machine(directory: impl Into<PathBuf>) -> Self {
        Self {
            directory: directory.into(),
            administrator_owned: true,
        }
    }

    pub(crate) fn validate_state_file(&self, file: &File) -> Result<(), ReleaseError> {
        #[cfg(windows)]
        if self.administrator_owned {
            return sirinvpn_platform::windows::administrator_files::validate_file(file)
                .map_err(|_| ReleaseError::UnsafeInstalledState);
        }
        files::validate_private_file(file).map_err(|_| ReleaseError::UnsafeInstalledState)
    }
    pub(crate) fn validate_state_directory(&self, path: &Path) -> Result<(), ReleaseError> {
        #[cfg(windows)]
        if self.administrator_owned {
            return sirinvpn_platform::windows::administrator_files::validate_directory(path)
                .map_err(|_| ReleaseError::UnsafeInstalledState);
        }
        files::validate_private_directory(path).map_err(|_| ReleaseError::UnsafeInstalledState)
    }
    pub(crate) fn create_state_directory(&self, path: &Path) -> std::io::Result<()> {
        #[cfg(windows)]
        if self.administrator_owned {
            return sirinvpn_platform::windows::administrator_files::create_directory(path);
        }
        files::create_private_directory(path)
    }
    pub(crate) fn open_state_lock(&self, path: &Path) -> std::io::Result<File> {
        #[cfg(windows)]
        if self.administrator_owned {
            return sirinvpn_platform::windows::administrator_files::open_lock(path);
        }
        files::open_private_lock(path)
    }
    pub(crate) fn restrict_state_file(&self, file: &File) -> std::io::Result<()> {
        #[cfg(windows)]
        if self.administrator_owned {
            return sirinvpn_platform::windows::administrator_files::restrict_file(file);
        }
        files::restrict_file(file)
    }
    pub(crate) fn write_state(&self, path: &Path, bytes: &[u8]) -> std::io::Result<()> {
        use std::io::Write;
        let parent = path.parent().ok_or(std::io::ErrorKind::InvalidInput)?;
        let mut temporary = self.temporary_state_file(parent, ".release-")?;
        temporary.write_all(bytes)?;
        files::persist(temporary, path, true)?;
        Ok(())
    }
    pub(crate) fn temporary_state_file(
        &self,
        parent: &Path,
        prefix: &str,
    ) -> std::io::Result<tempfile::NamedTempFile> {
        #[cfg(windows)]
        if self.administrator_owned {
            return tempfile::Builder::new().prefix(prefix).make_in(
                parent,
                sirinvpn_platform::windows::administrator_files::create_file,
            );
        }
        let file = tempfile::Builder::new()
            .prefix(prefix)
            .tempfile_in(parent)?;
        self.restrict_state_file(file.as_file())?;
        Ok(file)
    }
}
