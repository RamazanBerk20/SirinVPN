//! AppImage/APK release state. A signed baseline must match the installed bytes.
//! Preparing an update never commits installation. The platform performs its
//! replacement, then an independent read of the installed artifact commits last.
mod records;
#[cfg(test)]
mod tests;

use crate::{
    ArtifactKind, BUNDLED_RELEASE_TRUST_ROOT_PEM, InstallationDecisionKind,
    InstalledReleaseReceipt, InstalledReleaseStore, InstalledReleaseSummary, ReleaseArtifact,
    ReleaseError, ReleaseManifest, VerifiedReleaseTrustPolicy,
    installed_release::{
        VerifiedCandidate, evaluate_with_key_transition, finish_locked, summarize,
        verify_candidate_with_trust,
    },
};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

pub struct ClientReleaseBundle<'a> {
    pub manifest: &'a [u8],
    pub signature: &'a [u8],
    pub artifact_directory: &'a Path,
    pub kind: ArtifactKind,
    pub target: &'a str,
}

#[derive(Clone, Debug, Serialize)]
pub struct ClientReleaseStatus {
    pub installed: Option<InstalledReleaseSummary>,
    pub pending_version: Option<String>,
    pub rollback_version: Option<String>,
}

#[derive(Debug)]
pub struct PreparedClientRelease {
    pub artifact: PathBuf,
    pub state: InstalledReleaseSummary,
    pub baseline_bound: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ClientUpdateJournal {
    schema_version: u16,
    previous: InstalledReleaseReceipt,
    candidate: InstalledReleaseReceipt,
}

impl InstalledReleaseStore {
    /// Native installers revalidate this immediately before giving bytes to
    /// the OS. Neither a caller-provided digest nor UI approval is authenticity.
    pub fn verify_pending_client_artifact(
        &self,
        installed: &Path,
        candidate: &Path,
        kind: ArtifactKind,
        target: &str,
    ) -> Result<InstalledReleaseSummary, ReleaseError> {
        self.verify_pending_client_with_root(
            installed,
            candidate,
            kind,
            target,
            BUNDLED_RELEASE_TRUST_ROOT_PEM,
        )
    }

    fn verify_pending_client_with_root(
        &self,
        installed: &Path,
        candidate: &Path,
        kind: ArtifactKind,
        target: &str,
        root: &str,
    ) -> Result<InstalledReleaseSummary, ReleaseError> {
        if !self.validate_existing_directory()? {
            return Err(ReleaseError::ClientBaselineRequired);
        }
        let lock = self.open_lock()?;
        FileExt::lock_shared(&lock)?;
        let result = (|| {
            let journal = self
                .read_client_journal()?
                .ok_or(ReleaseError::ClientUpdatePending)?;
            let artifact = &journal.candidate.active_artifact;
            if artifact.kind != kind
                || artifact.target != target
                || self.validate_cached_artifact_unlocked(artifact)? != candidate
            {
                return Err(ReleaseError::ClientUpdateUnsupported);
            }
            require_installed(installed, &journal.previous.active_artifact)?;
            if self.read_receipt_unlocked()?.as_ref() != Some(&journal.previous) {
                return Err(ReleaseError::InvalidClientUpdateJournal);
            }
            authorize_receipt(&journal.candidate, &self.client_trust_unlocked(root)?)?;
            Ok(summarize(&journal.candidate))
        })();
        finish_locked(lock, result)
    }

    pub fn prepare_client_release(
        &self,
        bundle: &ClientReleaseBundle<'_>,
        installed: &Path,
        running_version: &str,
    ) -> Result<PreparedClientRelease, ReleaseError> {
        self.prepare_client_with_root(
            bundle,
            installed,
            running_version,
            BUNDLED_RELEASE_TRUST_ROOT_PEM,
        )
    }

    fn prepare_client_with_root(
        &self,
        bundle: &ClientReleaseBundle<'_>,
        installed: &Path,
        running_version: &str,
        root: &str,
    ) -> Result<PreparedClientRelease, ReleaseError> {
        self.ensure_directory()?;
        let lock = self.open_lock()?;
        FileExt::lock_exclusive(&lock)?;
        let result = (|| {
            if self.read_client_journal()?.is_some() {
                return Err(ReleaseError::ClientUpdatePending);
            }
            require_kind(bundle.kind)?;
            let trust = self.client_trust_unlocked(root)?;
            let (candidate, key) = verify_candidate_with_trust(
                bundle.manifest,
                bundle.signature,
                &trust,
                bundle.artifact_directory,
                bundle.kind,
                bundle.target,
            )?;
            require_support(&candidate.release.manifest)?;
            let previous = self.read_receipt_unlocked()?;
            if let Some(previous) = &previous {
                require_track(previous, &candidate.artifact)?;
                require_installed(installed, &previous.active_artifact)?;
                if previous.active_release.manifest.release_version != running_version {
                    return Err(ReleaseError::ClientInstalledMismatch);
                }
            } else if candidate.release.manifest.release_version != running_version
                || require_installed(installed, &candidate.artifact).is_err()
            {
                return Err(ReleaseError::ClientBaselineRequired);
            }
            let (receipt, action) =
                evaluate_with_key_transition(previous.clone(), candidate, key, false, true)?;
            let artifact =
                self.cache_artifact_unlocked(bundle.artifact_directory, &receipt.active_artifact)?;
            let baseline_bound = matches!(
                action,
                InstallationDecisionKind::Initialize | InstallationDecisionKind::AlreadyBound
            );
            if baseline_bound {
                self.write_receipt_unlocked(&receipt)?;
                self.cleanup_client_cache(&receipt)?;
            } else {
                if action != InstallationDecisionKind::Upgrade {
                    return Err(ReleaseError::ClientUpdateUnsupported);
                }
                self.write_client_journal(&ClientUpdateJournal {
                    schema_version: 1,
                    previous: previous.ok_or(ReleaseError::ClientBaselineRequired)?,
                    candidate: receipt.clone(),
                })?;
            }
            Ok(PreparedClientRelease {
                artifact,
                state: summarize(&receipt),
                baseline_bound,
            })
        })();
        finish_locked(lock, result)
    }

    /// The caller supplies the platform's installed package path, never a
    /// downloaded candidate path. Android obtains it from ApplicationInfo.
    pub fn finish_client_release(&self, installed: &Path) -> Result<bool, ReleaseError> {
        self.finish_client_with_root(installed, BUNDLED_RELEASE_TRUST_ROOT_PEM)
    }

    fn finish_client_with_root(&self, installed: &Path, root: &str) -> Result<bool, ReleaseError> {
        if !self.validate_existing_directory()? {
            return Ok(false);
        }
        let lock = self.open_lock()?;
        FileExt::lock_exclusive(&lock)?;
        let result = (|| {
            let Some(journal) = self.read_client_journal()? else {
                return Ok(false);
            };
            if require_installed(installed, &journal.previous.active_artifact).is_ok() {
                return Ok(false);
            }
            require_installed(installed, &journal.candidate.active_artifact)?;
            authorize_receipt(&journal.candidate, &self.client_trust_unlocked(root)?)?;
            let current = self
                .read_receipt_unlocked()?
                .ok_or(ReleaseError::InvalidClientUpdateJournal)?;
            if current != journal.previous && current != journal.candidate {
                return Err(ReleaseError::InvalidClientUpdateJournal);
            }
            self.write_receipt_unlocked(&journal.candidate)?;
            self.write_client_previous(&journal.previous)?;
            self.remove_client_journal()?;
            self.cleanup_client_cache(&journal.candidate)?;
            Ok(true)
        })();
        finish_locked(lock, result)
    }

    /// Only cancel after the platform has abandoned its installer session.
    /// A replacement that already reached disk must be finalized, not erased.
    pub fn cancel_client_release(&self, installed: &Path) -> Result<(), ReleaseError> {
        if !self.validate_existing_directory()? {
            return Ok(());
        }
        let lock = self.open_lock()?;
        FileExt::lock_exclusive(&lock)?;
        let result = (|| {
            let Some(journal) = self.read_client_journal()? else {
                return Ok(());
            };
            require_installed(installed, &journal.previous.active_artifact)?;
            if self.read_receipt_unlocked()?.as_ref() != Some(&journal.previous) {
                return Err(ReleaseError::InvalidClientUpdateJournal);
            }
            self.remove_client_journal()?;
            self.cleanup_client_cache(&journal.previous)
        })();
        finish_locked(lock, result)
    }

    /// AppImage replacement executes while holding the receipt lock. The
    /// closure must replace only the already-validated installed file atomically.
    pub fn replace_prepared_appimage(
        &self,
        installed: &Path,
        replace: impl FnOnce(&Path, &ReleaseArtifact) -> Result<(), ReleaseError>,
    ) -> Result<(), ReleaseError> {
        self.replace_appimage_with_root(installed, replace, BUNDLED_RELEASE_TRUST_ROOT_PEM)
    }

    fn replace_appimage_with_root(
        &self,
        installed: &Path,
        replace: impl FnOnce(&Path, &ReleaseArtifact) -> Result<(), ReleaseError>,
        root: &str,
    ) -> Result<(), ReleaseError> {
        if !self.validate_existing_directory()? {
            return Err(ReleaseError::ClientBaselineRequired);
        }
        let lock = self.open_lock()?;
        FileExt::lock_exclusive(&lock)?;
        let result = (|| {
            let journal = self
                .read_client_journal()?
                .ok_or(ReleaseError::ClientUpdatePending)?;
            if journal.candidate.active_artifact.kind != ArtifactKind::LinuxAppImage {
                return Err(ReleaseError::ClientUpdateUnsupported);
            }
            require_installed(installed, &journal.previous.active_artifact)?;
            if self.read_receipt_unlocked()?.as_ref() != Some(&journal.previous) {
                return Err(ReleaseError::InvalidClientUpdateJournal);
            }
            authorize_receipt(&journal.candidate, &self.client_trust_unlocked(root)?)?;
            let candidate =
                self.validate_cached_artifact_unlocked(&journal.candidate.active_artifact)?;
            replace(&candidate, &journal.candidate.active_artifact)?;
            require_installed(installed, &journal.candidate.active_artifact)?;
            self.write_receipt_unlocked(&journal.candidate)?;
            self.write_client_previous(&journal.previous)?;
            self.remove_client_journal()?;
            self.cleanup_client_cache(&journal.candidate)
        })();
        finish_locked(lock, result)
    }

    pub fn prepare_appimage_rollback(
        &self,
        installed: &Path,
    ) -> Result<PreparedClientRelease, ReleaseError> {
        self.prepare_rollback_with_root(installed, BUNDLED_RELEASE_TRUST_ROOT_PEM)
    }

    fn prepare_rollback_with_root(
        &self,
        installed: &Path,
        root: &str,
    ) -> Result<PreparedClientRelease, ReleaseError> {
        if !self.validate_existing_directory()? {
            return Err(ReleaseError::ClientRollbackUnavailable);
        }
        let lock = self.open_lock()?;
        FileExt::lock_exclusive(&lock)?;
        let result = (|| {
            if self.read_client_journal()?.is_some() {
                return Err(ReleaseError::ClientUpdatePending);
            }
            let current = self
                .read_receipt_unlocked()?
                .ok_or(ReleaseError::ClientBaselineRequired)?;
            let retained = self
                .read_client_previous()?
                .ok_or(ReleaseError::ClientRollbackUnavailable)?;
            if current.active_artifact.kind != ArtifactKind::LinuxAppImage {
                return Err(ReleaseError::ClientUpdateUnsupported);
            }
            require_track(&current, &retained.active_artifact)?;
            require_installed(installed, &current.active_artifact)?;
            let key = authorize_receipt(&retained, &self.client_trust_unlocked(root)?)?;
            let (candidate, action) = evaluate_with_key_transition(
                Some(current.clone()),
                VerifiedCandidate {
                    release: retained.active_release,
                    artifact: retained.active_artifact,
                },
                key,
                true,
                true,
            )?;
            if action != InstallationDecisionKind::Rollback {
                return Err(ReleaseError::ClientRollbackUnavailable);
            }
            let artifact = self.validate_cached_artifact_unlocked(&candidate.active_artifact)?;
            self.write_client_journal(&ClientUpdateJournal {
                schema_version: 1,
                previous: current,
                candidate: candidate.clone(),
            })?;
            Ok(PreparedClientRelease {
                artifact,
                state: summarize(&candidate),
                baseline_bound: false,
            })
        })();
        finish_locked(lock, result)
    }

    pub fn inspect_client_release(&self) -> Result<ClientReleaseStatus, ReleaseError> {
        let empty = ClientReleaseStatus {
            installed: None,
            pending_version: None,
            rollback_version: None,
        };
        if !self.validate_existing_directory()? {
            return Ok(empty);
        }
        let lock = self.open_lock()?;
        FileExt::lock_shared(&lock)?;
        let result = (|| {
            let installed = self
                .read_receipt_unlocked()?
                .map(|receipt| summarize(&receipt));
            let pending_version = self
                .read_client_journal()?
                .map(|journal| journal.candidate.active_release.manifest.release_version);
            let rollback_version = self
                .read_client_previous()?
                .filter(|previous| {
                    installed.as_ref().is_some_and(|current| {
                        current.active_artifact.kind == ArtifactKind::LinuxAppImage
                            && previous.active_release.manifest.release_sequence
                                < current.active_release_sequence
                    })
                })
                .map(|receipt| receipt.active_release.manifest.release_version);
            Ok(ClientReleaseStatus {
                installed,
                pending_version,
                rollback_version,
            })
        })();
        finish_locked(lock, result)
    }

    fn client_trust_unlocked(
        &self,
        root: &str,
    ) -> Result<VerifiedReleaseTrustPolicy, ReleaseError> {
        let trust = self
            .read_trust_unlocked_with_root(root)?
            .ok_or(ReleaseError::InstalledTrustRequired)?;
        crate::trust::verify_installed_trust(&trust, root)
    }
}

fn require_kind(kind: ArtifactKind) -> Result<(), ReleaseError> {
    if !matches!(kind, ArtifactKind::LinuxAppImage | ArtifactKind::AndroidApk) {
        return Err(ReleaseError::ClientUpdateUnsupported);
    }
    Ok(())
}

fn require_support(manifest: &ReleaseManifest) -> Result<(), ReleaseError> {
    if !manifest.state_compatibility.iter().any(|state| {
        state.state == "client_release_transaction"
            && state.reads.minimum <= 1
            && state.reads.maximum >= 1
            && state.writes.minimum <= 1
            && state.writes.maximum >= 1
    }) {
        return Err(ReleaseError::ClientUpdateUnsupported);
    }
    Ok(())
}

fn require_installed(installed: &Path, artifact: &ReleaseArtifact) -> Result<(), ReleaseError> {
    let (size, digest) = crate::digest_artifact(installed)?;
    if size != artifact.size_bytes || digest != artifact.sha256 {
        return Err(ReleaseError::ClientInstalledMismatch);
    }
    Ok(())
}

fn require_track(
    current: &InstalledReleaseReceipt,
    artifact: &ReleaseArtifact,
) -> Result<(), ReleaseError> {
    require_kind(artifact.kind)?;
    require_support(&current.active_release.manifest)?;
    if current.active_artifact.kind != artifact.kind
        || current.active_artifact.target != artifact.target
    {
        return Err(ReleaseError::ClientUpdateUnsupported);
    }
    Ok(())
}

fn authorize_receipt(
    receipt: &InstalledReleaseReceipt,
    trust: &VerifiedReleaseTrustPolicy,
) -> Result<String, ReleaseError> {
    crate::verify_manifest_with_trust_policy(
        &crate::encode_manifest(&receipt.active_release.manifest)?,
        &crate::encode_signature(&receipt.active_release.signature)?,
        trust,
    )?;
    trust
        .policy
        .active_release_keys
        .iter()
        .find(|key| key.key_id_sha256 == receipt.active_release.signature.key_id_sha256)
        .map(|key| key.public_key_pem.clone())
        .ok_or(ReleaseError::ReleaseKeyNotTrusted)
}
