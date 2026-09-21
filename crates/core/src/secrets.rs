use crate::SecretIdentity;
#[cfg(not(any(windows, target_os = "android")))]
use keyring::Entry;
#[cfg(not(target_os = "android"))]
use std::fs;
use std::{io, path::PathBuf};
use thiserror::Error;
#[cfg(not(target_os = "android"))]
use zeroize::Zeroizing;

#[cfg(not(any(windows, target_os = "android")))]
const KEYRING_SERVICE: &str = "org.sirinvpn.client";

pub trait SecretStore: Send + Sync {
    fn put(&self, reference: &str, secret: &SecretIdentity) -> Result<(), SecretStoreError>;
    fn get(&self, reference: &str) -> Result<SecretIdentity, SecretStoreError>;
    fn delete(&self, reference: &str) -> Result<(), SecretStoreError>;
}

#[derive(Debug, Error)]
pub enum SecretStoreError {
    #[error("secret does not exist")]
    NotFound,
    #[error("secure storage is unavailable: {0}")]
    Unavailable(String),
    #[error("secret storage data is invalid")]
    InvalidData,
    #[error("secret file operation failed: {0}")]
    Io(#[from] io::Error),
}

pub struct HybridSecretStore {
    #[cfg_attr(target_os = "android", allow(dead_code))]
    fallback_directory: PathBuf,
}

impl HybridSecretStore {
    pub fn new(fallback_directory: PathBuf) -> Self {
        Self { fallback_directory }
    }

    #[cfg(not(any(windows, target_os = "android")))]
    fn entry(reference: &str) -> Result<Entry, SecretStoreError> {
        Entry::new(KEYRING_SERVICE, reference)
            .map_err(|error| SecretStoreError::Unavailable(error.to_string()))
    }

    #[cfg(not(target_os = "android"))]
    fn fallback_path(&self, reference: &str) -> Result<PathBuf, SecretStoreError> {
        if reference.is_empty()
            || reference.len() > 128
            || !reference
                .chars()
                .all(|character| character.is_ascii_alphanumeric() || character == '-')
        {
            return Err(SecretStoreError::InvalidData);
        }
        #[cfg(not(windows))]
        let extension = "json";
        #[cfg(windows)]
        let extension = "dpapi";
        Ok(self
            .fallback_directory
            .join(format!("{reference}.{extension}")))
    }

    #[cfg(not(any(windows, target_os = "android")))]
    fn put_fallback(&self, reference: &str, bytes: &[u8]) -> Result<(), SecretStoreError> {
        sirinvpn_platform::files::create_private_directory(&self.fallback_directory)?;
        let path = self.fallback_path(reference)?;
        sirinvpn_platform::files::atomic_write(&path, bytes, true)?;
        Ok(())
    }
}

#[cfg(not(any(windows, target_os = "android")))]
impl SecretStore for HybridSecretStore {
    fn put(&self, reference: &str, secret: &SecretIdentity) -> Result<(), SecretStoreError> {
        let bytes =
            Zeroizing::new(serde_json::to_vec(secret).map_err(|_| SecretStoreError::InvalidData)?);
        if let Ok(entry) = Self::entry(reference)
            && entry.set_secret(&bytes).is_ok()
        {
            return Ok(());
        }
        self.put_fallback(reference, &bytes)
    }

    fn get(&self, reference: &str) -> Result<SecretIdentity, SecretStoreError> {
        if let Ok(entry) = Self::entry(reference)
            && let Ok(bytes) = entry.get_secret()
        {
            let bytes = Zeroizing::new(bytes);
            return serde_json::from_slice(&bytes).map_err(|_| SecretStoreError::InvalidData);
        }
        let path = self.fallback_path(reference)?;
        let bytes = Zeroizing::new(fs::read(path).map_err(|error| {
            if error.kind() == io::ErrorKind::NotFound {
                SecretStoreError::NotFound
            } else {
                SecretStoreError::Io(error)
            }
        })?);
        serde_json::from_slice(&bytes).map_err(|_| SecretStoreError::InvalidData)
    }

    fn delete(&self, reference: &str) -> Result<(), SecretStoreError> {
        if let Ok(entry) = Self::entry(reference) {
            let _ = entry.delete_credential();
        }
        let path = self.fallback_path(reference)?;
        match fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        }
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
        android_store()?.put(reference, secret)
    }
    fn get(&self, reference: &str) -> Result<SecretIdentity, SecretStoreError> {
        android_store()?.get(reference)
    }
    fn delete(&self, reference: &str) -> Result<(), SecretStoreError> {
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
