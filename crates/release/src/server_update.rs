//! Authenticated, recoverable replacement of the VPS executable. The host owns
//! service control and validates real server state; this module owns trust,
//! rollback boundaries, durable receipts, and the two-artifact recovery cache.

mod journal;
#[cfg(test)]
mod tests;
mod transition;

use crate::{
    ArtifactKind, BUNDLED_RELEASE_TRUST_ROOT_PEM, InstallationDecision, InstallationDecisionKind,
    InstalledReleaseReceipt, InstalledReleaseStore, InstalledReleaseSummary, ReleaseError,
    ReleaseManifest, VerifiedReleaseTrustPolicy, digest_artifact,
    installed_release::{
        decision, evaluate_with_key_transition, finish_locked, summarize,
        verify_candidate_with_trust,
    },
};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Only verified cache files are passed to host methods that execute a binary.
/// The lock must also exclude installation/repair and manual server replacement.
pub trait ServerReleaseHost {
    fn lock(&self) -> Result<Box<dyn Send>, ReleaseError>;
    fn installed_binary(&self) -> &Path;
    fn preflight(&self, executable: &Path, manifest: &ReleaseManifest) -> Result<(), ReleaseError>;
    fn stop(&self) -> Result<(), ReleaseError>;
    fn replace(&self, executable: &Path) -> Result<(), ReleaseError>;
    fn start(&self) -> Result<(), ReleaseError>;
    fn health(&self) -> Result<(), ReleaseError>;
    /// Refresh the independently installed recovery coordinator only after the
    /// receipt commits, while the durable transaction can still be recovered.
    fn complete(&self) -> Result<(), ReleaseError> {
        Ok(())
    }
}

pub struct ServerReleaseBundle<'a> {
    pub manifest: &'a [u8],
    pub signature: &'a [u8],
    pub artifact_directory: &'a Path,
    pub target: &'a str,
}

#[derive(Clone, Debug, Serialize)]
pub struct ServerReleaseStatus {
    pub installed: Option<InstalledReleaseSummary>,
    pub rollback_version: Option<String>,
    pub recovery_pending: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ServerRecoveryAction {
    NothingPending,
    RestoredPreviousRelease,
    FinalizedCandidateRelease,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ServerUpdateJournal {
    schema_version: u16,
    previous: InstalledReleaseReceipt,
    candidate: InstalledReleaseReceipt,
}

impl InstalledReleaseStore {
    /// Bind a signed baseline only when its exact bytes are already installed.
    /// Initial installation/repair is responsible for its own rollback until
    /// this receipt is committed. This API never blesses an unknown executable.
    pub fn adopt_trusted_server(
        &self,
        bundle: &ServerReleaseBundle<'_>,
        host: &dyn ServerReleaseHost,
    ) -> Result<InstallationDecision, ReleaseError> {
        self.adopt_server_with_root(bundle, host, BUNDLED_RELEASE_TRUST_ROOT_PEM)
    }

    fn adopt_server_with_root(
        &self,
        bundle: &ServerReleaseBundle<'_>,
        host: &dyn ServerReleaseHost,
        root: &str,
    ) -> Result<InstallationDecision, ReleaseError> {
        self.ensure_directory()?;
        let _host_lock = host.lock()?;
        let lock = self.open_lock()?;
        FileExt::lock_exclusive(&lock)?;
        let result = (|| {
            self.require_no_server_journal()?;
            let trust = self.server_trust_unlocked(root)?;
            let (candidate, key) = verify_candidate_with_trust(
                bundle.manifest,
                bundle.signature,
                &trust,
                bundle.artifact_directory,
                ArtifactKind::ServerElf,
                bundle.target,
            )?;
            require_server_support(&candidate.release.manifest)?;
            let current = self.read_receipt_unlocked()?;
            let (receipt, action) =
                evaluate_with_key_transition(current, candidate, key, false, true)?;
            if !matches!(
                action,
                InstallationDecisionKind::Initialize | InstallationDecisionKind::AlreadyBound
            ) {
                return Err(ReleaseError::ServerReceiptRequired);
            }
            require_installed_matches(host, &receipt)?;
            let cache =
                self.cache_artifact_unlocked(bundle.artifact_directory, &receipt.active_artifact)?;
            host.preflight(&cache, &receipt.active_release.manifest)?;
            host.health()?;
            self.write_receipt_unlocked(&receipt)?;
            host.complete()?;
            self.cleanup_server_cache_unlocked(&receipt)?;
            Ok(decision(action, &receipt))
        })();
        finish_locked(lock, result)
    }

    pub fn install_trusted_server(
        &self,
        bundle: &ServerReleaseBundle<'_>,
        host: &dyn ServerReleaseHost,
    ) -> Result<InstallationDecision, ReleaseError> {
        self.install_server_with_root(bundle, host, BUNDLED_RELEASE_TRUST_ROOT_PEM)
    }

    fn install_server_with_root(
        &self,
        bundle: &ServerReleaseBundle<'_>,
        host: &dyn ServerReleaseHost,
        root: &str,
    ) -> Result<InstallationDecision, ReleaseError> {
        if !self.validate_existing_directory()? {
            return Err(ReleaseError::ServerReceiptRequired);
        }
        let _host_lock = host.lock()?;
        let lock = self.open_lock()?;
        FileExt::lock_exclusive(&lock)?;
        let result = (|| {
            self.recover_server_unlocked(host, true)?;
            let trust = self.server_trust_unlocked(root)?;
            let (candidate, key) = verify_candidate_with_trust(
                bundle.manifest,
                bundle.signature,
                &trust,
                bundle.artifact_directory,
                ArtifactKind::ServerElf,
                bundle.target,
            )?;
            let previous = self
                .read_receipt_unlocked()?
                .ok_or(ReleaseError::ServerReceiptRequired)?;
            require_same_server_target(&previous, &candidate.artifact)?;
            require_server_support(&previous.active_release.manifest)?;
            require_server_support(&candidate.release.manifest)?;
            require_installed_matches(host, &previous)?;
            let (proposed, action) =
                evaluate_with_key_transition(Some(previous.clone()), candidate, key, false, true)?;
            if action == InstallationDecisionKind::AlreadyBound {
                return Ok(decision(action, &proposed));
            }
            if action != InstallationDecisionKind::Upgrade {
                return Err(ReleaseError::ServerUpdateUnsupported);
            }
            self.cache_artifact_unlocked(bundle.artifact_directory, &proposed.active_artifact)?;
            self.transition_server_unlocked(previous, proposed, action, host)
        })();
        finish_locked(lock, result)
    }

    /// Rollback is explicit and limited to the retained previous release. It
    /// must still be authorized by the current trust policy and read live state.
    pub fn rollback_trusted_server(
        &self,
        host: &dyn ServerReleaseHost,
    ) -> Result<InstallationDecision, ReleaseError> {
        self.rollback_server_with_root(host, BUNDLED_RELEASE_TRUST_ROOT_PEM)
    }

    fn rollback_server_with_root(
        &self,
        host: &dyn ServerReleaseHost,
        root: &str,
    ) -> Result<InstallationDecision, ReleaseError> {
        if !self.validate_existing_directory()? {
            return Err(ReleaseError::ServerReceiptRequired);
        }
        let _host_lock = host.lock()?;
        let lock = self.open_lock()?;
        FileExt::lock_exclusive(&lock)?;
        let result = (|| {
            self.recover_server_unlocked(host, true)?;
            let previous = self
                .read_receipt_unlocked()?
                .ok_or(ReleaseError::ServerReceiptRequired)?;
            require_installed_matches(host, &previous)?;
            let retained = self
                .read_server_previous()?
                .ok_or(ReleaseError::ServerRollbackUnavailable)?;
            require_same_server_target(&previous, &retained.active_artifact)?;
            require_server_support(&retained.active_release.manifest)?;
            let trust = self.server_trust_unlocked(root)?;
            let manifest = crate::encode_manifest(&retained.active_release.manifest)?;
            let signature = crate::encode_signature(&retained.active_release.signature)?;
            crate::verify_manifest_with_trust_policy(&manifest, &signature, &trust)?;
            let key = trust
                .policy
                .active_release_keys
                .iter()
                .find(|key| key.key_id_sha256 == retained.active_release.signature.key_id_sha256)
                .ok_or(ReleaseError::ReleaseKeyNotTrusted)?
                .public_key_pem
                .clone();
            let candidate = crate::installed_release::VerifiedCandidate {
                release: retained.active_release,
                artifact: retained.active_artifact,
            };
            let (proposed, action) =
                evaluate_with_key_transition(Some(previous.clone()), candidate, key, true, true)?;
            if action != InstallationDecisionKind::Rollback {
                return Err(ReleaseError::ServerRollbackUnavailable);
            }
            self.transition_server_unlocked(previous, proposed, action, host)
        })();
        finish_locked(lock, result)
    }

    /// At boot, restore bytes before the network services start. The host must
    /// not recursively start systemd dependencies when `start_service` is false.
    pub fn recover_server(
        &self,
        host: &dyn ServerReleaseHost,
        start_service: bool,
    ) -> Result<ServerRecoveryAction, ReleaseError> {
        if !self.validate_existing_directory()? {
            return Ok(ServerRecoveryAction::NothingPending);
        }
        let _host_lock = host.lock()?;
        let lock = self.open_lock()?;
        FileExt::lock_exclusive(&lock)?;
        let result = self.recover_server_unlocked(host, start_service);
        finish_locked(lock, result)
    }

    pub fn inspect_server_release(&self) -> Result<ServerReleaseStatus, ReleaseError> {
        let empty = ServerReleaseStatus {
            installed: None,
            rollback_version: None,
            recovery_pending: false,
        };
        if !self.validate_existing_directory()? {
            return Ok(empty);
        }
        let lock = self.open_lock()?;
        FileExt::lock_shared(&lock)?;
        let result = (|| {
            let installed = self.read_receipt_unlocked()?.map(|value| summarize(&value));
            let rollback_version = self
                .read_server_previous()?
                .filter(|value| {
                    installed.as_ref().is_some_and(|current| {
                        value.active_release.manifest.release_sequence
                            < current.active_release_sequence
                    })
                })
                .map(|value| value.active_release.manifest.release_version);
            let recovery_pending = self.read_server_journal()?.is_some();
            Ok(ServerReleaseStatus {
                installed,
                rollback_version,
                recovery_pending,
            })
        })();
        finish_locked(lock, result)
    }

    fn server_trust_unlocked(
        &self,
        root: &str,
    ) -> Result<VerifiedReleaseTrustPolicy, ReleaseError> {
        let trust = self
            .read_trust_unlocked_with_root(root)?
            .ok_or(ReleaseError::InstalledTrustRequired)?;
        crate::trust::verify_installed_trust(&trust, root)
    }
}

fn require_server_support(manifest: &ReleaseManifest) -> Result<(), ReleaseError> {
    for name in [
        "server_release_transaction",
        "server_handoff_guard",
        "server_maintenance_guard",
    ] {
        if !manifest.state_compatibility.iter().any(|state| {
            state.state == name
                && state.reads.minimum <= 1
                && state.reads.maximum >= 1
                && state.writes.minimum <= 1
                && state.writes.maximum >= 1
        }) {
            return Err(ReleaseError::ServerUpdateUnsupported);
        }
    }
    Ok(())
}

fn require_installed_matches(
    host: &dyn ServerReleaseHost,
    receipt: &InstalledReleaseReceipt,
) -> Result<(), ReleaseError> {
    let (size, digest) = digest_artifact(host.installed_binary())?;
    if size != receipt.active_artifact.size_bytes || digest != receipt.active_artifact.sha256 {
        return Err(ReleaseError::ServerInstalledMismatch);
    }
    Ok(())
}

fn require_same_server_target(
    current: &InstalledReleaseReceipt,
    artifact: &crate::ReleaseArtifact,
) -> Result<(), ReleaseError> {
    if current.active_artifact.kind != ArtifactKind::ServerElf
        || artifact.kind != ArtifactKind::ServerElf
        || current.active_artifact.target != artifact.target
    {
        return Err(ReleaseError::ServerUpdateUnsupported);
    }
    Ok(())
}
