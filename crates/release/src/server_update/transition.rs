use super::*;

impl InstalledReleaseStore {
    pub(super) fn transition_server_unlocked(
        &self,
        previous: InstalledReleaseReceipt,
        candidate: InstalledReleaseReceipt,
        action: InstallationDecisionKind,
        host: &dyn ServerReleaseHost,
    ) -> Result<InstallationDecision, ReleaseError> {
        let previous_path = self.validate_cached_artifact_unlocked(&previous.active_artifact)?;
        let candidate_path = self.validate_cached_artifact_unlocked(&candidate.active_artifact)?;
        host.preflight(&candidate_path, &candidate.active_release.manifest)?;
        let journal = ServerUpdateJournal {
            schema_version: 1,
            previous,
            candidate,
        };
        self.write_server_journal(&journal)?;
        let result: Result<InstallationDecision, ReleaseError> = (|| {
            host.stop()?;
            // Authorization cannot change during these final compatibility checks.
            // Both readers must preserve all state that either version can write.
            host.preflight(&previous_path, &journal.previous.active_release.manifest)?;
            host.preflight(&candidate_path, &journal.candidate.active_release.manifest)?;
            host.replace(&candidate_path)?;
            require_installed_matches(host, &journal.candidate)?;
            host.start()?;
            host.health()?;
            self.write_receipt_unlocked(&journal.candidate)?;
            // Updating the retained rollback pointer is part of finalization.
            // A failure before receipt commit must preserve the older pointer.
            self.write_server_previous(&journal.previous)?;
            host.complete()?;
            self.remove_server_journal()?;
            self.cleanup_server_cache_unlocked(&journal.candidate)?;
            Ok(decision(action, &journal.candidate))
        })();
        match result {
            Ok(value) => Ok(value),
            Err(_) => match self.recover_server_unlocked(host, true) {
                Ok(ServerRecoveryAction::RestoredPreviousRelease) => {
                    Err(ReleaseError::ServerUpdateRolledBack)
                }
                Ok(ServerRecoveryAction::FinalizedCandidateRelease) => {
                    Ok(decision(action, &journal.candidate))
                }
                Ok(ServerRecoveryAction::NothingPending) => {
                    // A durable receipt and journal removal may precede a cache
                    // cleanup error. Never undo a committed healthy release.
                    if self.read_receipt_unlocked()?.as_ref() == Some(&journal.candidate) {
                        Ok(decision(action, &journal.candidate))
                    } else {
                        Err(ReleaseError::ServerUpdateRecoveryRequired)
                    }
                }
                Err(_) => Err(ReleaseError::ServerUpdateRecoveryRequired),
            },
        }
    }

    pub(super) fn recover_server_unlocked(
        &self,
        host: &dyn ServerReleaseHost,
        start_service: bool,
    ) -> Result<ServerRecoveryAction, ReleaseError> {
        let Some(journal) = self.read_server_journal()? else {
            return Ok(ServerRecoveryAction::NothingPending);
        };
        let current = self
            .read_receipt_unlocked()?
            .ok_or(ReleaseError::InvalidServerUpdateJournal)?;
        let committed = if current == journal.candidate {
            true
        } else if current == journal.previous {
            false
        } else {
            return Err(ReleaseError::InvalidServerUpdateJournal);
        };
        let selected = if committed {
            &journal.candidate
        } else {
            &journal.previous
        };
        let cache = self.validate_cached_artifact_unlocked(&selected.active_artifact)?;
        if start_service {
            host.stop()?;
        }
        host.preflight(&cache, &selected.active_release.manifest)?;
        host.replace(&cache)?;
        require_installed_matches(host, selected)?;
        if start_service {
            host.start()?;
            host.health()?;
        }
        if committed {
            self.write_server_previous(&journal.previous)?;
        }
        host.complete()?;
        // The selected receipt is already durable. Configuration is deliberately
        // never rewound: revocations and policies remain at their current state.
        self.remove_server_journal()?;
        self.cleanup_server_cache_unlocked(selected)?;
        Ok(if committed {
            ServerRecoveryAction::FinalizedCandidateRelease
        } else {
            ServerRecoveryAction::RestoredPreviousRelease
        })
    }
}
