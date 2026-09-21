use super::*;
use crate::installed_release::{validate_private_file_metadata, validate_receipt};
use serde::de::DeserializeOwned;
use std::{fs, io::Read};

const JOURNAL: &str = "server-transaction.json";
const PREVIOUS: &str = "server-previous.json";
const MAX_RECORD_BYTES: u64 = 2 * 1024 * 1024;

impl InstalledReleaseStore {
    pub(super) fn require_no_server_journal(&self) -> Result<(), ReleaseError> {
        if self.read_server_journal()?.is_some() {
            return Err(ReleaseError::ServerUpdateRecoveryRequired);
        }
        Ok(())
    }

    pub(super) fn read_server_journal(&self) -> Result<Option<ServerUpdateJournal>, ReleaseError> {
        let Some(journal): Option<ServerUpdateJournal> = self.read_server_record(JOURNAL)? else {
            return Ok(None);
        };
        if journal.schema_version != 1 {
            return Err(ReleaseError::InvalidServerUpdateJournal);
        }
        self.validate_server_record(&journal.previous)?;
        self.validate_server_record(&journal.candidate)?;
        require_same_server_target(&journal.previous, &journal.candidate.active_artifact)?;
        let (expected, action) = evaluate_with_key_transition(
            Some(journal.previous.clone()),
            crate::installed_release::VerifiedCandidate {
                release: journal.candidate.active_release.clone(),
                artifact: journal.candidate.active_artifact.clone(),
            },
            journal.candidate.trusted_public_key_pem.clone(),
            true,
            true,
        )?;
        if expected != journal.candidate
            || !matches!(
                action,
                InstallationDecisionKind::Upgrade | InstallationDecisionKind::Rollback
            )
        {
            return Err(ReleaseError::InvalidServerUpdateJournal);
        }
        Ok(Some(journal))
    }

    pub(super) fn read_server_previous(
        &self,
    ) -> Result<Option<InstalledReleaseReceipt>, ReleaseError> {
        let receipt = self.read_server_record(PREVIOUS)?;
        if let Some(value) = &receipt {
            self.validate_server_record(value)?;
        }
        Ok(receipt)
    }

    pub(super) fn write_server_journal(
        &self,
        journal: &ServerUpdateJournal,
    ) -> Result<(), ReleaseError> {
        self.validate_server_record(&journal.previous)?;
        self.validate_server_record(&journal.candidate)?;
        self.write_server_record(JOURNAL, journal)
    }

    pub(super) fn write_server_previous(
        &self,
        receipt: &InstalledReleaseReceipt,
    ) -> Result<(), ReleaseError> {
        self.validate_server_record(receipt)?;
        self.write_server_record(PREVIOUS, receipt)
    }

    pub(super) fn remove_server_journal(&self) -> Result<(), ReleaseError> {
        fs::remove_file(self.state_directory().join(JOURNAL))?;
        sirinvpn_platform::files::sync_directory(self.state_directory())?;
        Ok(())
    }

    pub(super) fn cleanup_server_cache_unlocked(
        &self,
        receipt: &InstalledReleaseReceipt,
    ) -> Result<(), ReleaseError> {
        let previous = self.read_server_previous()?;
        let mut retained = vec![&receipt.active_artifact];
        if let Some(previous) = &previous {
            retained.push(&previous.active_artifact);
        }
        self.cleanup_cached_artifacts_unlocked(&retained)
    }

    fn validate_server_record(
        &self,
        receipt: &InstalledReleaseReceipt,
    ) -> Result<(), ReleaseError> {
        validate_receipt(receipt)?;
        require_server_support(&receipt.active_release.manifest)?;
        require_same_server_target(receipt, &receipt.active_artifact)?;
        self.validate_cached_artifact_unlocked(&receipt.active_artifact)?;
        Ok(())
    }

    fn read_server_record<T: DeserializeOwned + Serialize>(
        &self,
        name: &str,
    ) -> Result<Option<T>, ReleaseError> {
        let file =
            match sirinvpn_platform::files::open_no_follow(&self.state_directory().join(name)) {
                Ok(file) => file,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
                Err(error) => return Err(error.into()),
            };
        let metadata = file.metadata()?;
        self.validate_state_file(&file)?;
        validate_private_file_metadata(&metadata)?;
        if metadata.len() == 0 || metadata.len() > MAX_RECORD_BYTES {
            return Err(ReleaseError::InvalidServerUpdateJournal);
        }
        let mut bytes = Vec::new();
        file.take(MAX_RECORD_BYTES + 1).read_to_end(&mut bytes)?;
        if bytes.len() as u64 > MAX_RECORD_BYTES {
            return Err(ReleaseError::InvalidServerUpdateJournal);
        }
        let value: T =
            serde_json::from_slice(&bytes).map_err(|_| ReleaseError::InvalidServerUpdateJournal)?;
        if crate::canonical_json(&value)? != bytes {
            return Err(ReleaseError::InvalidServerUpdateJournal);
        }
        Ok(Some(value))
    }

    fn write_server_record<T: Serialize>(&self, name: &str, value: &T) -> Result<(), ReleaseError> {
        let bytes = crate::canonical_json(value)?;
        if bytes.len() as u64 > MAX_RECORD_BYTES {
            return Err(ReleaseError::InvalidServerUpdateJournal);
        }
        self.write_state(&self.state_directory().join(name), &bytes)?;
        Ok(())
    }
}
