use crate::SecretIdentity;
#[cfg(not(target_os = "android"))]
use std::fs;
use std::{io, path::PathBuf};
use thiserror::Error;
#[cfg(not(target_os = "android"))]
use zeroize::Zeroizing;

#[cfg(not(any(windows, target_os = "android")))]
mod linux;
#[cfg(windows)]
mod windows;
#[cfg(not(any(windows, target_os = "android")))]
pub use linux::{StoragePolicy, StorageStatus};

pub fn validate_reference(reference: &str) -> Result<(), SecretStoreError> {
    if reference.is_empty()
        || reference.len() > 128
        || !reference
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'-')
    {
        return Err(SecretStoreError::InvalidData);
    }
    Ok(())
}

pub trait SecretStore: Send + Sync {
    fn put(&self, reference: &str, secret: &SecretIdentity) -> Result<(), SecretStoreError>;
    fn get(&self, reference: &str) -> Result<SecretIdentity, SecretStoreError>;
    fn delete(&self, reference: &str) -> Result<(), SecretStoreError>;
    /// Preflight for a freshly generated random reference; put must still validate it.
    fn new_reference_available(&self, reference: &str) -> Result<bool, SecretStoreError> {
        match self.get(reference) {
            Err(SecretStoreError::NotFound) => Ok(true),
            Ok(_) => Ok(false),
            Err(error) => Err(error),
        }
    }
}

#[derive(Debug, Error)]
pub enum SecretStoreError {
    #[error("secret does not exist")]
    NotFound,
    #[error("secure storage is unavailable: {0}")]
    Unavailable(String),
    #[error("secret storage data is invalid")]
    InvalidData,
    #[error("credential cleanup is incomplete; unlock the secure store and retry cleanup")]
    CleanupPending,
    #[error("credential deletion was requested; this identity cannot be used or rewritten")]
    Deleted,
    #[error(
        "credential storage transition is incomplete; retry the operation or credential cleanup"
    )]
    TransitionPending,
    #[error(
        "secure storage is required; unlock the keyring or explicitly allow permission-protected file storage"
    )]
    SecureStoreRequired,
    #[error("secret file operation failed: {0}")]
    Io(#[from] io::Error),
}

pub struct HybridSecretStore {
    #[cfg_attr(target_os = "android", allow(dead_code))]
    fallback_directory: PathBuf,
    #[cfg(not(any(windows, target_os = "android")))]
    backend: Box<dyn linux::KeyringBackend>,
}

impl HybridSecretStore {
    pub fn new(fallback_directory: PathBuf) -> Self {
        Self {
            fallback_directory,
            #[cfg(not(any(windows, target_os = "android")))]
            backend: Box::new(linux::SystemKeyring),
        }
    }

    #[cfg(not(target_os = "android"))]
    fn lock(&self, reference: &str) -> Result<fs::File, SecretStoreError> {
        validate_reference(reference)?;
        self.lock_file(&format!("{reference}.lock"))
    }

    #[cfg(not(target_os = "android"))]
    fn lock_file(&self, name: &str) -> Result<fs::File, SecretStoreError> {
        use fs2::FileExt;
        use sirinvpn_platform::files;
        if !self.fallback_directory.try_exists()? {
            files::create_private_directory(&self.fallback_directory)?;
        }
        files::validate_private_directory(&self.fallback_directory)?;
        let lock = files::open_private_lock(&self.fallback_directory.join(name))?;
        files::validate_private_file(&lock)?;
        // Status and membership reads can arrive together. Serialize brief operations,
        // but keep a stalled credential worker from blocking every caller indefinitely.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        loop {
            match lock.try_lock_exclusive() {
                Ok(()) => break,
                Err(error)
                    if error.raw_os_error() == fs2::lock_contended_error().raw_os_error() =>
                {
                    if std::time::Instant::now() >= deadline {
                        return Err(SecretStoreError::Unavailable(
                            "credential operation already in progress; retry".into(),
                        ));
                    }
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
                Err(error) => return Err(error.into()),
            }
        }
        Ok(lock)
    }

    #[cfg(not(target_os = "android"))]
    fn read_private(&self, name: &str) -> Result<Vec<u8>, SecretStoreError> {
        use sirinvpn_platform::files;
        use std::io::Read;
        let file = files::open_no_follow(&self.fallback_directory.join(name)).map_err(|error| {
            if error.kind() == io::ErrorKind::NotFound {
                SecretStoreError::NotFound
            } else {
                error.into()
            }
        })?;
        files::validate_private_file(&file)?;
        let mut bytes = Vec::new();
        file.take(73729).read_to_end(&mut bytes)?;
        if bytes.len() > 73728 {
            return Err(SecretStoreError::InvalidData);
        }
        Ok(bytes)
    }

    #[cfg(not(target_os = "android"))]
    fn fallback_path(&self, reference: &str) -> Result<PathBuf, SecretStoreError> {
        validate_reference(reference)?;
        #[cfg(not(windows))]
        let extension = "json";
        #[cfg(windows)]
        let extension = "dpapi";
        Ok(self
            .fallback_directory
            .join(format!("{reference}.{extension}")))
    }
}

#[cfg(target_os = "android")]
static ANDROID_STORE: std::sync::OnceLock<Box<dyn SecretStore>> = std::sync::OnceLock::new();

/// Installed once by the service-owned JNI runtime. Never falls back to a file.
#[cfg(target_os = "android")]
pub fn install_android_secret_store(store: Box<dyn SecretStore>) -> Result<(), SecretStoreError> {
    ANDROID_STORE
        .set(store)
        .map_err(|_| SecretStoreError::Unavailable("already initialized".into()))
}

#[cfg(target_os = "android")]
fn android_store() -> Result<&'static dyn SecretStore, SecretStoreError> {
    ANDROID_STORE.get().map(Box::as_ref).ok_or_else(|| {
        SecretStoreError::Unavailable("unlock and initialize the Android service".into())
    })
}

#[cfg(target_os = "android")]
impl SecretStore for HybridSecretStore {
    fn put(&self, reference: &str, secret: &SecretIdentity) -> Result<(), SecretStoreError> {
        validate_reference(reference)?;
        android_store()?.put(reference, secret)
    }
    fn get(&self, reference: &str) -> Result<SecretIdentity, SecretStoreError> {
        validate_reference(reference)?;
        android_store()?.get(reference)
    }
    fn delete(&self, reference: &str) -> Result<(), SecretStoreError> {
        validate_reference(reference)?;
        android_store()?.delete(reference)
    }
}
