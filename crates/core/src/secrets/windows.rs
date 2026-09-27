use super::*;
use serde::{Deserialize, Serialize};
use sirinvpn_platform::files;

#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum DeletionState {
    Deleting,
    Deleted,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DeletionRecord {
    schema_version: u16,
    state: DeletionState,
}

impl HybridSecretStore {
    fn deletion_path(&self, reference: &str) -> PathBuf {
        self.fallback_directory
            .join(format!("{reference}.state.json"))
    }

    // Callers validate the reference and hold its cross-process lock first.
    fn deletion_record(&self, reference: &str) -> Result<Option<DeletionRecord>, SecretStoreError> {
        let bytes = match self.read_private(&format!("{reference}.state.json")) {
            Ok(bytes) => bytes,
            Err(SecretStoreError::NotFound) => return Ok(None),
            Err(error) => return Err(error),
        };
        if bytes.len() > 256 {
            return Err(SecretStoreError::InvalidData);
        }
        let record: DeletionRecord =
            serde_json::from_slice(&bytes).map_err(|_| SecretStoreError::InvalidData)?;
        if record.schema_version != 2 {
            return Err(SecretStoreError::InvalidData);
        }
        Ok(Some(record))
    }

    fn save_deletion(&self, reference: &str, state: DeletionState) -> Result<(), SecretStoreError> {
        let bytes = serde_json::to_vec(&DeletionRecord {
            schema_version: 2,
            state,
        })
        .map_err(|_| SecretStoreError::InvalidData)?;
        files::atomic_write(&self.deletion_path(reference), &bytes, true)?;
        Ok(())
    }
}

impl SecretStore for HybridSecretStore {
    fn put(&self, reference: &str, secret: &SecretIdentity) -> Result<(), SecretStoreError> {
        use sirinvpn_platform::windows::dpapi::{self, Scope};
        let _lock = self.lock(reference)?;
        if self.deletion_record(reference)?.is_some() {
            return Err(SecretStoreError::Deleted);
        }
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
        let _lock = self.lock(reference)?;
        if self.deletion_record(reference)?.is_some() {
            return Err(SecretStoreError::Deleted);
        }
        let encrypted = self.read_private(&format!("{reference}.dpapi"))?;
        let plaintext = dpapi::unprotect(
            &encrypted,
            Scope::User,
            &format!("device-identity:{reference}"),
        )?;
        serde_json::from_slice(&plaintext).map_err(|_| SecretStoreError::InvalidData)
    }

    fn delete(&self, reference: &str) -> Result<(), SecretStoreError> {
        let _lock = self.lock(reference)?;
        self.deletion_record(reference)?; // Do not silently replace malformed state.
        // A durable tombstone is the authority boundary. Once published, neither
        // a crash nor a writer waiting on this lock can resurrect the reference.
        self.save_deletion(reference, DeletionState::Deleting)?;
        #[cfg(test)]
        tests::checkpoint(self, "intent");
        let path = self.fallback_path(reference)?;
        match fs::remove_file(&path) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(_) => return Err(SecretStoreError::CleanupPending),
        }
        match fs::symlink_metadata(&path) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            _ => return Err(SecretStoreError::CleanupPending),
        }
        #[cfg(test)]
        tests::checkpoint(self, "removed");
        self.save_deletion(reference, DeletionState::Deleted)
            .map_err(|_| SecretStoreError::CleanupPending)?;
        #[cfg(test)]
        tests::checkpoint(self, "complete");
        Ok(())
    }

    fn new_reference_available(&self, reference: &str) -> Result<bool, SecretStoreError> {
        let _lock = self.lock(reference)?;
        if self.deletion_record(reference)?.is_some() {
            return Ok(false);
        }
        match fs::symlink_metadata(self.fallback_path(reference)?) {
            Ok(_) => Ok(false),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(true),
            Err(error) => Err(error.into()),
        }
    }
}

#[cfg(test)]
mod tests;
