use super::*;
use serde::de::DeserializeOwned;
use std::{fs, io::Read};

const JOURNAL: &str = "client-transaction.json";
const PREVIOUS: &str = "client-previous.json";
const MAX_BYTES: u64 = 2 * 1024 * 1024;

impl InstalledReleaseStore {
    pub(super) fn read_client_journal(&self) -> Result<Option<ClientUpdateJournal>, ReleaseError> {
        let Some(journal): Option<ClientUpdateJournal> = self.read_client_record(JOURNAL)? else {
            return Ok(None);
        };
        if journal.schema_version != 1 {
            return Err(ReleaseError::InvalidClientUpdateJournal);
        }
        self.validate_client_record(&journal.previous)?;
        self.validate_client_record(&journal.candidate)?;
        require_track(&journal.previous, &journal.candidate.active_artifact)?;
        let (expected, action) = evaluate_with_key_transition(
            Some(journal.previous.clone()),
            VerifiedCandidate {
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
            return Err(ReleaseError::InvalidClientUpdateJournal);
        }
        Ok(Some(journal))
    }
    pub(super) fn read_client_previous(
        &self,
    ) -> Result<Option<InstalledReleaseReceipt>, ReleaseError> {
        let record = self.read_client_record(PREVIOUS)?;
        if let Some(receipt) = &record {
            self.validate_client_record(receipt)?;
        }
        Ok(record)
    }
    pub(super) fn write_client_previous(
        &self,
        receipt: &InstalledReleaseReceipt,
    ) -> Result<(), ReleaseError> {
        self.validate_client_record(receipt)?;
        self.write_client_record(PREVIOUS, receipt)
    }
    pub(super) fn write_client_journal(
        &self,
        journal: &ClientUpdateJournal,
    ) -> Result<(), ReleaseError> {
        self.validate_client_record(&journal.previous)?;
        self.validate_client_record(&journal.candidate)?;
        self.write_client_record(JOURNAL, journal)
    }
    pub(super) fn remove_client_journal(&self) -> Result<(), ReleaseError> {
        fs::remove_file(self.state_directory().join(JOURNAL))?;
        sirinvpn_platform::files::sync_directory(self.state_directory())?;
        Ok(())
    }
    pub(super) fn cleanup_client_cache(
        &self,
        receipt: &InstalledReleaseReceipt,
    ) -> Result<(), ReleaseError> {
        let previous = self.read_client_previous()?;
        let mut retained = vec![&receipt.active_artifact];
        if let Some(previous) = &previous {
            retained.push(&previous.active_artifact);
        }
        self.cleanup_cached_artifacts_unlocked(&retained)
    }
    fn validate_client_record(
        &self,
        receipt: &InstalledReleaseReceipt,
    ) -> Result<(), ReleaseError> {
        crate::installed_release::validate_receipt(receipt)?;
        require_kind(receipt.active_artifact.kind)?;
        require_support(&receipt.active_release.manifest)?;
        self.validate_cached_artifact_unlocked(&receipt.active_artifact)?;
        Ok(())
    }
    fn read_client_record<T: DeserializeOwned + Serialize>(
        &self,
        name: &str,
    ) -> Result<Option<T>, ReleaseError> {
        let file =
            match sirinvpn_platform::files::open_no_follow(&self.state_directory().join(name)) {
                Ok(file) => file,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
                Err(error) => return Err(error.into()),
            };
        self.validate_state_file(&file)?;
        let metadata = file.metadata()?;
        crate::installed_release::validate_private_file_metadata(&metadata)?;
        if metadata.len() == 0 || metadata.len() > MAX_BYTES {
            return Err(ReleaseError::InvalidClientUpdateJournal);
        }
        let mut bytes = Vec::new();
        file.take(MAX_BYTES + 1).read_to_end(&mut bytes)?;
        if bytes.len() as u64 > MAX_BYTES {
            return Err(ReleaseError::InvalidClientUpdateJournal);
        }
        let value =
            serde_json::from_slice(&bytes).map_err(|_| ReleaseError::InvalidClientUpdateJournal)?;
        if crate::canonical_json(&value)? != bytes {
            return Err(ReleaseError::InvalidClientUpdateJournal);
        }
        Ok(Some(value))
    }
    fn write_client_record<T: Serialize>(&self, name: &str, value: &T) -> Result<(), ReleaseError> {
        let bytes = crate::canonical_json(value)?;
        if bytes.len() as u64 > MAX_BYTES {
            return Err(ReleaseError::InvalidClientUpdateJournal);
        }
        self.write_state(&self.state_directory().join(name), &bytes)?;
        Ok(())
    }
}
