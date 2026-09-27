//! One authoritative backend per identity. Locks cover all processes, including CLI/UI.
use super::*;
use ed25519_dalek::{SigningKey, pkcs8::DecodePrivateKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sirinvpn_platform::files;

pub(super) trait KeyringBackend: Send + Sync {
    fn put(&self, reference: &str, bytes: &[u8]) -> Result<(), SecretStoreError>;
    fn get(&self, reference: &str) -> Result<Vec<u8>, SecretStoreError>;
    fn delete(&self, reference: &str) -> Result<(), SecretStoreError>;
}

pub(super) struct SystemKeyring;
#[cfg(target_os = "linux")]
mod system;
#[cfg(not(target_os = "linux"))]
fn entry(reference: &str) -> Result<keyring::Entry, SecretStoreError> {
    keyring::Entry::new("org.sirinvpn.client", reference).map_err(keyring_error)
}
#[cfg(not(target_os = "linux"))]
fn keyring_error(error: keyring::Error) -> SecretStoreError {
    match error {
        keyring::Error::NoEntry => SecretStoreError::NotFound,
        _ => {
            SecretStoreError::Unavailable("system keyring did not acknowledge the operation".into())
        }
    }
}
#[cfg(not(target_os = "linux"))]
impl KeyringBackend for SystemKeyring {
    fn put(&self, reference: &str, bytes: &[u8]) -> Result<(), SecretStoreError> {
        entry(reference)?.set_secret(bytes).map_err(keyring_error)
    }
    fn get(&self, reference: &str) -> Result<Vec<u8>, SecretStoreError> {
        entry(reference)?.get_secret().map_err(keyring_error)
    }
    fn delete(&self, reference: &str) -> Result<(), SecretStoreError> {
        entry(reference)?.delete_credential().map_err(keyring_error)
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StoragePolicy {
    #[default]
    SecureStoreRequired,
    AllowPrivateFile,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Backend {
    Writing,
    Keyring,
    PrivateFile,
    Deleting,
    Deleted,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    schema_version: u16,
    backend: Backend,
    // Fingerprint of both public keys; never a private-key copy or activity record.
    binding: String,
}

#[derive(Debug, Serialize)]
pub struct StorageStatus {
    pub policy: StoragePolicy,
    pub backend: &'static str,
    pub protection: &'static str,
    pub availability: &'static str,
    pub cleanup_pending: bool,
}

fn identity(bytes: &[u8]) -> Result<(SecretIdentity, String), SecretStoreError> {
    let secret: SecretIdentity =
        serde_json::from_slice(bytes).map_err(|_| SecretStoreError::InvalidData)?;
    let wg = crate::wireguard_public_key_from_private(&secret.wireguard_private_key)
        .map_err(|_| SecretStoreError::InvalidData)?;
    let management = SigningKey::from_pkcs8_pem(&secret.management_private_key_pem)
        .map_err(|_| SecretStoreError::InvalidData)?;
    let mut hash = Sha256::new();
    hash.update(wg.as_bytes());
    hash.update(management.verifying_key().as_bytes());
    Ok((secret, hex::encode(hash.finalize())))
}

impl HybridSecretStore {
    fn record(&self, reference: &str) -> Result<Option<Record>, SecretStoreError> {
        let bytes = match self.read_private(&format!("{reference}.state.json")) {
            Err(SecretStoreError::NotFound) => return Ok(None),
            result => result?,
        };
        let record: Record =
            serde_json::from_slice(&bytes).map_err(|_| SecretStoreError::InvalidData)?;
        if record.schema_version != 2
            || (!record.binding.is_empty()
                && (record.binding.len() != 64
                    || !record.binding.bytes().all(|b| b.is_ascii_hexdigit())))
        {
            return Err(SecretStoreError::InvalidData);
        }
        Ok(Some(record))
    }

    fn save_record(
        &self,
        reference: &str,
        backend: Backend,
        binding: &str,
    ) -> Result<(), SecretStoreError> {
        let bytes = serde_json::to_vec(&Record {
            schema_version: 2,
            backend,
            binding: binding.into(),
        })
        .map_err(|_| SecretStoreError::InvalidData)?;
        files::atomic_write(
            &self
                .fallback_directory
                .join(format!("{reference}.state.json")),
            &bytes,
            true,
        )?;
        Ok(())
    }

    pub fn policy(&self) -> Result<StoragePolicy, SecretStoreError> {
        let _lock = self.lock_file(".storage-policy.lock")?;
        self.policy_locked()
    }

    fn policy_locked(&self) -> Result<StoragePolicy, SecretStoreError> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Policy {
            schema_version: u16,
            policy: StoragePolicy,
        }
        match self.read_private(".storage-policy.json") {
            Err(SecretStoreError::NotFound) => Ok(StoragePolicy::default()),
            Ok(bytes) => {
                let policy: Policy =
                    serde_json::from_slice(&bytes).map_err(|_| SecretStoreError::InvalidData)?;
                if policy.schema_version != 1 {
                    return Err(SecretStoreError::InvalidData);
                }
                Ok(policy.policy)
            }
            Err(error) => Err(error),
        }
    }

    pub fn set_policy(&self, policy: StoragePolicy) -> Result<(), SecretStoreError> {
        let _lock = self.lock_file(".storage-policy.lock")?;
        let bytes = serde_json::to_vec(&serde_json::json!({"schema_version":1,"policy":policy}))
            .map_err(|_| SecretStoreError::InvalidData)?;
        files::atomic_write(
            &self.fallback_directory.join(".storage-policy.json"),
            &bytes,
            true,
        )?;
        Ok(())
    }

    fn get_locked(&self, reference: &str) -> Result<SecretIdentity, SecretStoreError> {
        let record = self.record(reference)?;
        let bytes = match record.as_ref().map(|r| r.backend) {
            Some(Backend::Deleting | Backend::Deleted) => return Err(SecretStoreError::Deleted),
            Some(Backend::Writing) => return Err(SecretStoreError::TransitionPending),
            Some(Backend::Keyring) => Zeroizing::new(self.backend.get(reference)?),
            Some(Backend::PrivateFile) => {
                Zeroizing::new(self.read_private(&format!("{reference}.json"))?)
            }
            None => {
                let file = self.read_private(&format!("{reference}.json"));
                match self.backend.get(reference) {
                    Ok(bytes) => {
                        let bytes = Zeroizing::new(bytes);
                        let (_, key_binding) = identity(&bytes)?;
                        match file {
                            Ok(file) => {
                                if identity(&Zeroizing::new(file))?.1 != key_binding {
                                    return Err(SecretStoreError::InvalidData);
                                }
                            }
                            Err(SecretStoreError::NotFound) => {}
                            Err(error) => return Err(error),
                        }
                        bytes
                    }
                    Err(SecretStoreError::NotFound | SecretStoreError::Unavailable(_))
                        if file.is_ok() =>
                    {
                        // Legacy file remains usable, but status never calls unknown provenance verified.
                        Zeroizing::new(file?)
                    }
                    Err(error) => {
                        if let Err(file_error) = file
                            && !matches!(file_error, SecretStoreError::NotFound)
                        {
                            return Err(file_error);
                        }
                        return Err(error);
                    }
                }
            }
        };
        let (secret, binding) = identity(&bytes)?;
        if record.is_some_and(|record| record.binding != binding) {
            return Err(SecretStoreError::InvalidData);
        }
        Ok(secret)
    }

    fn remove_file(&self, reference: &str) -> Result<(), SecretStoreError> {
        match fs::remove_file(self.fallback_path(reference)?) {
            Ok(()) => {
                files::sync_directory(&self.fallback_directory)?;
                Ok(())
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                // A previous unlink may have succeeded before directory fsync failed.
                files::sync_directory(&self.fallback_directory)?;
                Ok(())
            }
            Err(error) => Err(error.into()),
        }
    }

    pub fn status(&self, reference: &str) -> Result<StorageStatus, SecretStoreError> {
        let _lock = self.lock(reference)?;
        let record = self.record(reference)?;
        let (backend, protection) = match record.as_ref().map(|r| r.backend) {
            Some(Backend::Keyring) => ("keyring", "system_secure_store"),
            Some(Backend::PrivateFile) => ("private_file", "permissions_only"),
            Some(Backend::Deleting | Backend::Deleted) => ("deletion_requested", "unavailable"),
            Some(Backend::Writing) => ("write_pending", "unverified"),
            None => ("legacy_unknown", "unverified"),
        };
        let availability = match self.get_locked(reference) {
            Ok(_) => "available",
            Err(SecretStoreError::NotFound) => "absent",
            Err(SecretStoreError::InvalidData) => "invalid",
            Err(_) => "unavailable",
        };
        let cleanup_pending = record.is_some_and(|record| {
            record.backend == Backend::Deleting
                || record.backend == Backend::Writing
                || record.backend == Backend::Keyring
                    && self.fallback_path(reference).is_ok_and(|p| p.exists())
        });
        Ok(StorageStatus {
            policy: self.policy_locked()?,
            backend,
            protection,
            availability,
            cleanup_pending,
        })
    }

    /// Return references only to native callers; web APIs expose opaque profile IDs/status.
    pub fn pending_cleanup(&self) -> Result<Vec<String>, SecretStoreError> {
        let _lock = self.lock_file(".cleanup-list.lock")?;
        let mut pending = Vec::new();
        for entry in fs::read_dir(&self.fallback_directory)? {
            let name = entry?.file_name();
            let Some(reference) = name.to_str().and_then(|s| s.strip_suffix(".state.json")) else {
                continue;
            };
            validate_reference(reference)?;
            if self
                .record(reference)?
                .is_some_and(|r| matches!(r.backend, Backend::Deleting | Backend::Writing))
            {
                pending.push(reference.to_owned());
            }
        }
        Ok(pending)
    }

    pub fn migrate(&self, reference: &str, certificate: &str) -> Result<(), SecretStoreError> {
        let _lock = self.lock(reference)?;
        let secret = self.get_locked(reference)?;
        secret
            .public_identity(certificate)
            .map_err(|_| SecretStoreError::InvalidData)?;
        let bytes =
            Zeroizing::new(serde_json::to_vec(&secret).map_err(|_| SecretStoreError::InvalidData)?);
        let (_, binding) = identity(&bytes)?;
        self.backend.put(reference, &bytes)?;
        let readback = Zeroizing::new(self.backend.get(reference)?);
        if identity(&readback)?.1 != binding {
            return Err(SecretStoreError::InvalidData);
        }
        self.save_record(reference, Backend::Keyring, &binding)?;
        self.remove_file(reference)
            .map_err(|_| SecretStoreError::CleanupPending)
    }
}

impl SecretStore for HybridSecretStore {
    fn new_reference_available(&self, reference: &str) -> Result<bool, SecretStoreError> {
        let _lock = self.lock(reference)?;
        if self.record(reference)?.is_some() {
            return Ok(false);
        }
        match self.read_private(&format!("{reference}.json")) {
            Ok(_) => return Ok(false),
            Err(SecretStoreError::NotFound) => {}
            Err(error) => return Err(error),
        }
        match self.backend.get(reference) {
            Ok(_) => Ok(false),
            Err(SecretStoreError::NotFound) => Ok(true),
            Err(SecretStoreError::Unavailable(_))
                if self.policy()? == StoragePolicy::AllowPrivateFile =>
            {
                Ok(true)
            }
            Err(error) => Err(error),
        }
    }

    fn put(&self, reference: &str, secret: &SecretIdentity) -> Result<(), SecretStoreError> {
        let _lock = self.lock(reference)?;
        let _policy_lock = self.lock_file(".storage-policy.lock")?;
        let policy = self.policy_locked()?;
        let bytes =
            Zeroizing::new(serde_json::to_vec(secret).map_err(|_| SecretStoreError::InvalidData)?);
        let (_, binding) = identity(&bytes)?;
        if let Some(record) = self.record(reference)? {
            if matches!(record.backend, Backend::Deleting | Backend::Deleted) {
                return Err(SecretStoreError::Deleted);
            }
            if record.binding != binding {
                return Err(SecretStoreError::InvalidData);
            }
            if record.backend != Backend::Writing {
                let existing = self.get_locked(reference)?;
                drop(existing);
                files::sync_directory(&self.fallback_directory)?;
                return if record.backend == Backend::Keyring {
                    self.remove_file(reference)
                        .map_err(|_| SecretStoreError::CleanupPending)
                } else {
                    Ok(())
                };
            }
        } else if self.fallback_path(reference)?.exists() {
            // Never overwrite a legacy identity while its provenance is unknown.
            return Err(SecretStoreError::InvalidData);
        }
        // A reference is immutable even when it predates provenance records.
        match self.backend.get(reference) {
            Ok(existing) => {
                if identity(&Zeroizing::new(existing))?.1 != binding {
                    return Err(SecretStoreError::InvalidData);
                }
            }
            Err(SecretStoreError::NotFound | SecretStoreError::Unavailable(_)) => {}
            Err(error) => return Err(error),
        }
        self.save_record(reference, Backend::Writing, &binding)?;
        match self.backend.put(reference, &bytes) {
            Ok(()) => {
                let readback = Zeroizing::new(self.backend.get(reference)?);
                if identity(&readback)?.1 != binding {
                    return Err(SecretStoreError::InvalidData);
                }
                self.save_record(reference, Backend::Keyring, &binding)?;
                self.remove_file(reference)
                    .map_err(|_| SecretStoreError::CleanupPending)
            }
            Err(SecretStoreError::Unavailable(_)) if policy == StoragePolicy::AllowPrivateFile => {
                // Resume an interrupted install without overwriting a different copy.
                match self.read_private(&format!("{reference}.json")) {
                    Ok(existing) => {
                        if identity(&Zeroizing::new(existing))?.1 != binding {
                            return Err(SecretStoreError::InvalidData);
                        }
                        files::sync_directory(&self.fallback_directory)?;
                    }
                    Err(SecretStoreError::NotFound) => {
                        files::atomic_write(&self.fallback_path(reference)?, &bytes, false)?;
                    }
                    Err(error) => return Err(error),
                }
                self.save_record(reference, Backend::PrivateFile, &binding)
            }
            Err(SecretStoreError::Unavailable(_)) => Err(SecretStoreError::SecureStoreRequired),
            Err(error) => Err(error),
        }
    }

    fn get(&self, reference: &str) -> Result<SecretIdentity, SecretStoreError> {
        let _lock = self.lock(reference)?;
        self.get_locked(reference)
    }

    fn delete(&self, reference: &str) -> Result<(), SecretStoreError> {
        let _lock = self.lock(reference)?;
        if self
            .record(reference)?
            .is_some_and(|r| r.backend == Backend::Deleted)
        {
            files::sync_directory(&self.fallback_directory)?;
            return Ok(());
        }
        self.save_record(reference, Backend::Deleting, "")?;
        // Both attempts run. Keyring initialization failure is not confirmed absence.
        let keyring = self.backend.delete(reference);
        let fallback = self.remove_file(reference);
        if !matches!(keyring, Ok(()) | Err(SecretStoreError::NotFound)) || fallback.is_err() {
            return Err(SecretStoreError::CleanupPending);
        }
        self.save_record(reference, Backend::Deleted, "")
    }
}

#[cfg(test)]
mod tests;
