use crate::SecretIdentity;
#[cfg(not(target_os = "android"))]
use std::fs;
use std::{io, path::PathBuf};
use thiserror::Error;
#[cfg(not(target_os = "android"))]
use zeroize::Zeroizing;

#[cfg(not(any(windows, target_os = "android")))]
mod linux;
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

#[cfg(windows)]
impl SecretStore for HybridSecretStore {
    fn put(&self, reference: &str, secret: &SecretIdentity) -> Result<(), SecretStoreError> {
        use sirinvpn_platform::windows::dpapi::{self, Scope};
        let path = self.fallback_path(reference)?;
        let plaintext =
            Zeroizing::new(serde_json::to_vec(secret).map_err(|_| SecretStoreError::InvalidData)?);
        let encrypted = dpapi::protect(
            &plaintext,
            Scope::User,
            &format!("device-identity:{reference}"),
        )?;
        sirinvpn_platform::files::create_private_directory(&self.fallback_directory)?;
        sirinvpn_platform::files::atomic_write(&path, &encrypted, true)?;
        Ok(())
    }

    fn get(&self, reference: &str) -> Result<SecretIdentity, SecretStoreError> {
        use sirinvpn_platform::windows::dpapi::{self, Scope};
        let path = self.fallback_path(reference)?;
        let encrypted = sirinvpn_platform::files::read_bounded(&path, 73728).map_err(|error| {
            if error.kind() == io::ErrorKind::NotFound {
                SecretStoreError::NotFound
            } else {
                error.into()
            }
        })?;
        let plaintext = dpapi::unprotect(
            &encrypted,
            Scope::User,
            &format!("device-identity:{reference}"),
        )?;
        serde_json::from_slice(&plaintext).map_err(|_| SecretStoreError::InvalidData)
    }

    fn delete(&self, reference: &str) -> Result<(), SecretStoreError> {
        match fs::remove_file(self.fallback_path(reference)?) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        }
    }
}

#[cfg(all(test, windows))]
mod windows_tests {
    use super::*;
    #[test]
    fn windows_secrets_never_have_a_plaintext_fallback() {
        let directory = tempfile::tempdir().unwrap();
        let store = HybridSecretStore::new(directory.path().join("secrets"));
        let identity = crate::LocalIdentity::generate("Windows device").unwrap();
        store.put("test-device", &identity.secret).unwrap();
        let saved = fs::read(store.fallback_path("test-device").unwrap()).unwrap();
        assert!(!String::from_utf8_lossy(&saved).contains("PRIVATE KEY"));
        assert!(!directory.path().join("secrets/test-device.json").exists());
        assert_eq!(
            store
                .get("test-device")
                .unwrap()
                .public_identity(&identity.public.management_certificate_pem)
                .unwrap(),
            identity.public
        );
        store.delete("test-device").unwrap();
        assert!(matches!(
            store.get("test-device"),
            Err(SecretStoreError::NotFound)
        ));
    }
}
