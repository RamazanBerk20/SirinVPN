use crate::{
    ArtifactKind, InstallationDecision, InstallationDecisionKind, InstalledReleaseReceipt,
    InstalledReleaseStore, InstalledReleaseSummary, ReleaseArtifact, ReleaseError, ReleaseManifest,
    canonical_json, validate_artifact,
};
use fs2::FileExt;
use semver::Version;
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, OpenOptions},
    io::Read,
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

const TRANSACTION_SCHEMA_VERSION: u16 = 1;
const TRANSACTION_STATE_NAME: &str = "linux_release_transaction";
const JOURNAL_FILE_NAME: &str = "debian-update.json";
const MAX_JOURNAL_BYTES: u64 = 16 * 1024;
const MAX_COMMAND_OUTPUT_BYTES: usize = 64 * 1024;
const DEBIAN_PACKAGE_NAME: &str = "sirin-vpn";
const DPKG_PATH: &str = "/usr/bin/dpkg";
const DPKG_DEB_PATH: &str = "/usr/bin/dpkg-deb";
const DPKG_QUERY_PATH: &str = "/usr/bin/dpkg-query";
const HELPER_PATH: &str = "/usr/lib/sirinvpn/sirinvpn-helper";
const RELEASE_TOOL_PATH: &str = "/usr/lib/sirinvpn/sirinvpn-release";
const NETWORK_RUNTIME_DIRECTORY: &str = "/run/sirinvpn";
const NETWORK_OPERATION_LOCK: &str = "/run/sirinvpn/operation.lock";
const PERSISTENT_CONNECTION_PATH: &str = "/var/lib/sirinvpn/desired-connection.json";
const INSTALLED_EXECUTABLES: &[&str] = &[
    "/usr/bin/sirinvpn",
    "/usr/bin/sirinvpn-desktop",
    HELPER_PATH,
    RELEASE_TOOL_PATH,
    "/usr/lib/sirinvpn/sirinvpn-server",
];

#[derive(Clone, Copy)]
enum CommandFailure {
    InvalidPackage,
    Health,
}

impl CommandFailure {
    fn error(self) -> ReleaseError {
        match self {
            Self::InvalidPackage => ReleaseError::InvalidDebianPackage,
            Self::Health => ReleaseError::DebianPackageHealth,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DebianRecoveryAction {
    NothingPending,
    RestoredPreviousRelease,
    FinalizedCandidateRelease,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct DebianRecoveryResult {
    pub action: DebianRecoveryAction,
    pub state: InstalledReleaseSummary,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DebianUpdateJournal {
    schema_version: u16,
    previous_release_version: String,
    previous_manifest_sha256: String,
    previous_artifact: ReleaseArtifact,
    candidate_release_version: String,
    candidate_manifest_sha256: String,
    candidate_artifact: ReleaseArtifact,
}

trait DebianPackageManager {
    fn lock_network_operations(&self) -> Result<Box<dyn Send>, ReleaseError>;

    fn preflight_candidate(
        &self,
        package: &Path,
        expected_version: &str,
        target: &str,
    ) -> Result<(), ReleaseError>;

    fn install_package(&self, package: &Path, expected_version: &str) -> Result<(), ReleaseError>;

    fn check_installed_health(&self, expected_version: &str) -> Result<(), ReleaseError>;
}

struct SystemDebianPackageManager;

#[derive(Clone, Copy)]
enum CandidateTrust<'a> {
    Explicit(&'a str),
    Installed(&'a str),
}

impl InstalledReleaseStore {
    #[allow(clippy::too_many_arguments)]
    pub fn install_debian(
        &self,
        manifest_bytes: &[u8],
        signature_bytes: &[u8],
        trusted_public_key_pem: &str,
        artifact_directory: &Path,
        artifact_target: &str,
        allow_rollback: bool,
    ) -> Result<InstallationDecision, ReleaseError> {
        self.install_debian_with(
            manifest_bytes,
            signature_bytes,
            trusted_public_key_pem,
            artifact_directory,
            artifact_target,
            allow_rollback,
            &SystemDebianPackageManager,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn install_trusted_debian(
        &self,
        manifest_bytes: &[u8],
        signature_bytes: &[u8],
        artifact_directory: &Path,
        artifact_target: &str,
        allow_rollback: bool,
    ) -> Result<InstallationDecision, ReleaseError> {
        self.install_debian_with_trust(
            manifest_bytes,
            signature_bytes,
            CandidateTrust::Installed(crate::BUNDLED_RELEASE_TRUST_ROOT_PEM),
            artifact_directory,
            artifact_target,
            allow_rollback,
            &SystemDebianPackageManager,
        )
    }

    pub fn recover_debian(&self) -> Result<DebianRecoveryResult, ReleaseError> {
        self.recover_debian_with(&SystemDebianPackageManager)
    }

    #[allow(clippy::too_many_arguments)]
    fn install_debian_with(
        &self,
        manifest_bytes: &[u8],
        signature_bytes: &[u8],
        trusted_public_key_pem: &str,
        artifact_directory: &Path,
        artifact_target: &str,
        allow_rollback: bool,
        package_manager: &dyn DebianPackageManager,
    ) -> Result<InstallationDecision, ReleaseError> {
        self.install_debian_with_trust(
            manifest_bytes,
            signature_bytes,
            CandidateTrust::Explicit(trusted_public_key_pem),
            artifact_directory,
            artifact_target,
            allow_rollback,
            package_manager,
        )
    }

    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    fn install_trusted_debian_with_root(
        &self,
        manifest_bytes: &[u8],
        signature_bytes: &[u8],
        artifact_directory: &Path,
        artifact_target: &str,
        allow_rollback: bool,
        root_public_key_pem: &str,
        package_manager: &dyn DebianPackageManager,
    ) -> Result<InstallationDecision, ReleaseError> {
        self.install_debian_with_trust(
            manifest_bytes,
            signature_bytes,
            CandidateTrust::Installed(root_public_key_pem),
            artifact_directory,
            artifact_target,
            allow_rollback,
            package_manager,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn install_debian_with_trust(
        &self,
        manifest_bytes: &[u8],
        signature_bytes: &[u8],
        trust: CandidateTrust<'_>,
        artifact_directory: &Path,
        artifact_target: &str,
        allow_rollback: bool,
        package_manager: &dyn DebianPackageManager,
    ) -> Result<InstallationDecision, ReleaseError> {
        if !self.validate_existing_directory()? {
            return Err(ReleaseError::DebianUpdateReceiptRequired);
        }
        let lock = self.open_lock()?;
        FileExt::lock_exclusive(&lock)?;
        let result = (|| {
            let (candidate, canonical_key, allow_key_transition) = match trust {
                CandidateTrust::Explicit(public_key) => {
                    if self.trust_entry_exists_unlocked()? {
                        return Err(ReleaseError::InstalledTrustForbidsExplicitKey);
                    }
                    let (candidate, canonical_key) = crate::installed_release::verify_candidate(
                        manifest_bytes,
                        signature_bytes,
                        public_key,
                        artifact_directory,
                        ArtifactKind::LinuxDeb,
                        artifact_target,
                    )?;
                    (candidate, canonical_key, false)
                }
                CandidateTrust::Installed(root_public_key) => {
                    let trust = self
                        .read_trust_unlocked_with_root(root_public_key)?
                        .ok_or(ReleaseError::InstalledTrustRequired)?;
                    let verified_trust =
                        crate::trust::verify_installed_trust(&trust, root_public_key)?;
                    let (candidate, canonical_key) =
                        crate::installed_release::verify_candidate_with_trust(
                            manifest_bytes,
                            signature_bytes,
                            &verified_trust,
                            artifact_directory,
                            ArtifactKind::LinuxDeb,
                            artifact_target,
                        )?;
                    (candidate, canonical_key, true)
                }
            };
            let _network_guard = package_manager.lock_network_operations()?;
            self.recover_pending_unlocked(package_manager)?;
            let current = self
                .read_receipt_unlocked()?
                .ok_or(ReleaseError::DebianUpdateReceiptRequired)?;
            require_transaction_support(&current.active_release.manifest)?;
            require_transaction_support(&candidate.release.manifest)?;
            if current.active_artifact.kind != ArtifactKind::LinuxDeb
                || current.active_artifact.target != candidate.artifact.target
            {
                return Err(ReleaseError::DebianUpdateArtifactUnsupported);
            }
            let (proposed, action) = crate::installed_release::evaluate_with_key_transition(
                Some(current.clone()),
                candidate,
                canonical_key,
                allow_rollback,
                allow_key_transition,
            )?;
            if !matches!(
                action,
                InstallationDecisionKind::Upgrade
                    | InstallationDecisionKind::Rollback
                    | InstallationDecisionKind::AlreadyBound
            ) {
                return Err(ReleaseError::DebianUpdateArtifactUnsupported);
            }

            let previous_path = self.validate_cached_artifact_unlocked(&current.active_artifact)?;
            package_manager.preflight_candidate(
                &previous_path,
                &current.active_release.manifest.release_version,
                &current.active_artifact.target,
            )?;
            package_manager
                .check_installed_health(&current.active_release.manifest.release_version)?;
            let candidate_path =
                self.cache_artifact_unlocked(artifact_directory, &proposed.active_artifact)?;
            if candidate_path != previous_path
                && let Err(error) = package_manager.preflight_candidate(
                    &candidate_path,
                    &proposed.active_release.manifest.release_version,
                    &proposed.active_artifact.target,
                )
            {
                return cleanup_preflight_failure(self, &current, error);
            }
            if action == InstallationDecisionKind::AlreadyBound {
                self.cleanup_cached_artifacts_unlocked(&[&current.active_artifact])?;
                return Ok(crate::installed_release::decision(action, &current));
            }

            let journal = DebianUpdateJournal::new(&current, &proposed);
            self.write_journal_unlocked(&journal)?;
            let update_result = package_manager
                .install_package(
                    &candidate_path,
                    &proposed.active_release.manifest.release_version,
                )
                .and_then(|()| {
                    package_manager
                        .check_installed_health(&proposed.active_release.manifest.release_version)
                });
            if update_result.is_err() {
                return self.rollback_unlocked(&journal, package_manager);
            }

            #[cfg(feature = "test-release-fault-injection")]
            test_crash_at("before_receipt_commit", 86);
            if self.write_receipt_unlocked(&proposed).is_err() {
                match self.read_receipt_unlocked() {
                    Ok(Some(receipt)) if journal.matches_candidate(&receipt) => {}
                    Ok(Some(receipt)) if journal.matches_previous(&receipt) => {
                        return self.rollback_unlocked(&journal, package_manager);
                    }
                    _ => return Err(ReleaseError::DebianUpdateRecoveryRequired),
                }
            }
            #[cfg(feature = "test-release-fault-injection")]
            test_crash_at("after_receipt_commit", 87);
            if self.remove_journal_unlocked().is_err()
                || self
                    .cleanup_cached_artifacts_unlocked(&[&proposed.active_artifact])
                    .is_err()
            {
                return Err(ReleaseError::DebianUpdateRecoveryRequired);
            }
            Ok(crate::installed_release::decision(action, &proposed))
        })();
        crate::installed_release::finish_locked(lock, result)
    }

    fn recover_debian_with(
        &self,
        package_manager: &dyn DebianPackageManager,
    ) -> Result<DebianRecoveryResult, ReleaseError> {
        if !self.validate_existing_directory()? {
            return Err(ReleaseError::DebianUpdateReceiptRequired);
        }
        let lock = self.open_lock()?;
        FileExt::lock_exclusive(&lock)?;
        let result = (|| {
            let _network_guard = package_manager.lock_network_operations()?;
            let recovery = self.recover_pending_unlocked(package_manager)?;
            let receipt = self
                .read_receipt_unlocked()?
                .ok_or(ReleaseError::DebianUpdateReceiptRequired)?;
            if recovery.is_none() {
                self.cleanup_cached_artifacts_unlocked(&[&receipt.active_artifact])?;
            }
            Ok(DebianRecoveryResult {
                action: recovery.unwrap_or(DebianRecoveryAction::NothingPending),
                state: crate::installed_release::summarize(&receipt),
            })
        })();
        crate::installed_release::finish_locked(lock, result)
    }

    fn recover_pending_unlocked(
        &self,
        package_manager: &dyn DebianPackageManager,
    ) -> Result<Option<DebianRecoveryAction>, ReleaseError> {
        let Some(journal) = self.read_journal_unlocked()? else {
            return Ok(None);
        };
        let receipt = self
            .read_receipt_unlocked()?
            .ok_or(ReleaseError::InvalidDebianUpdateJournal)?;
        self.validate_cached_artifact_unlocked(&journal.previous_artifact)
            .map_err(|_| ReleaseError::InvalidDebianUpdateJournal)?;
        self.validate_cached_artifact_unlocked(&journal.candidate_artifact)
            .map_err(|_| ReleaseError::InvalidDebianUpdateJournal)?;

        let action = if journal.matches_candidate(&receipt) {
            let candidate_path =
                self.validate_cached_artifact_unlocked(&journal.candidate_artifact)?;
            package_manager
                .preflight_candidate(
                    &candidate_path,
                    &journal.candidate_release_version,
                    &journal.candidate_artifact.target,
                )
                .map_err(|_| ReleaseError::DebianUpdateRecoveryRequired)?;
            package_manager
                .check_installed_health(&journal.candidate_release_version)
                .map_err(|_| ReleaseError::DebianUpdateRecoveryRequired)?;
            DebianRecoveryAction::FinalizedCandidateRelease
        } else if journal.matches_previous(&receipt) {
            let previous_path = self
                .validate_cached_artifact_unlocked(&journal.previous_artifact)
                .map_err(|_| ReleaseError::DebianUpdateRecoveryRequired)?;
            package_manager
                .preflight_candidate(
                    &previous_path,
                    &journal.previous_release_version,
                    &journal.previous_artifact.target,
                )
                .and_then(|()| {
                    package_manager
                        .install_package(&previous_path, &journal.previous_release_version)
                })
                .and_then(|()| {
                    package_manager.check_installed_health(&journal.previous_release_version)
                })
                .map_err(|_| ReleaseError::DebianUpdateRecoveryRequired)?;
            DebianRecoveryAction::RestoredPreviousRelease
        } else {
            return Err(ReleaseError::InvalidDebianUpdateJournal);
        };

        self.remove_journal_unlocked()
            .map_err(|_| ReleaseError::DebianUpdateRecoveryRequired)?;
        self.cleanup_cached_artifacts_unlocked(&[&receipt.active_artifact])
            .map_err(|_| ReleaseError::DebianUpdateRecoveryRequired)?;
        Ok(Some(action))
    }

    fn rollback_unlocked(
        &self,
        journal: &DebianUpdateJournal,
        package_manager: &dyn DebianPackageManager,
    ) -> Result<InstallationDecision, ReleaseError> {
        let receipt = self
            .read_receipt_unlocked()
            .map_err(|_| ReleaseError::DebianUpdateRecoveryRequired)?
            .ok_or(ReleaseError::DebianUpdateRecoveryRequired)?;
        if !journal.matches_previous(&receipt) {
            return Err(ReleaseError::DebianUpdateRecoveryRequired);
        }
        let previous_path = self
            .validate_cached_artifact_unlocked(&journal.previous_artifact)
            .map_err(|_| ReleaseError::DebianUpdateRecoveryRequired)?;
        if package_manager
            .preflight_candidate(
                &previous_path,
                &journal.previous_release_version,
                &journal.previous_artifact.target,
            )
            .and_then(|()| {
                package_manager.install_package(&previous_path, &journal.previous_release_version)
            })
            .and_then(|()| {
                package_manager.check_installed_health(&journal.previous_release_version)
            })
            .is_err()
        {
            return Err(ReleaseError::DebianUpdateRecoveryRequired);
        }
        if self.remove_journal_unlocked().is_err()
            || self
                .cleanup_cached_artifacts_unlocked(&[&journal.previous_artifact])
                .is_err()
        {
            return Err(ReleaseError::DebianUpdateRecoveryRequired);
        }
        Err(ReleaseError::DebianUpdateRolledBack)
    }

    fn journal_path(&self) -> PathBuf {
        self.receipt_path()
            .parent()
            .expect("the receipt always has a state directory")
            .join(JOURNAL_FILE_NAME)
    }

    fn read_journal_unlocked(&self) -> Result<Option<DebianUpdateJournal>, ReleaseError> {
        let path = self.journal_path();
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        crate::installed_release::validate_private_file_metadata(&metadata)?;
        if metadata.len() == 0 || metadata.len() > MAX_JOURNAL_BYTES {
            return Err(ReleaseError::InvalidDebianUpdateJournal);
        }
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(path)?;
        crate::installed_release::validate_private_file_metadata(&file.metadata()?)?;
        let mut bytes = Vec::with_capacity(metadata.len() as usize);
        file.take(MAX_JOURNAL_BYTES + 1).read_to_end(&mut bytes)?;
        let journal: DebianUpdateJournal =
            serde_json::from_slice(&bytes).map_err(|_| ReleaseError::InvalidDebianUpdateJournal)?;
        journal.validate()?;
        if canonical_json(&journal)? != bytes {
            return Err(ReleaseError::NonCanonicalDebianUpdateJournal);
        }
        Ok(Some(journal))
    }

    fn write_journal_unlocked(&self, journal: &DebianUpdateJournal) -> Result<(), ReleaseError> {
        journal.validate()?;
        if self.read_journal_unlocked()?.is_some() {
            return Err(ReleaseError::DebianUpdateRecoveryRequired);
        }
        let bytes = canonical_json(journal)?;
        if bytes.len() as u64 > MAX_JOURNAL_BYTES {
            return Err(ReleaseError::InvalidDebianUpdateJournal);
        }
        let directory = self
            .receipt_path()
            .parent()
            .expect("the receipt always has a state directory")
            .to_path_buf();
        let mut temporary = tempfile::Builder::new()
            .prefix(".debian-update-")
            .tempfile_in(&directory)?;
        temporary
            .as_file()
            .set_permissions(fs::Permissions::from_mode(0o600))?;
        use std::io::Write;
        temporary.write_all(&bytes)?;
        temporary.as_file().sync_all()?;
        temporary
            .persist_noclobber(self.journal_path())
            .map_err(|error| error.error)?;
        File::open(directory)?.sync_all()?;
        Ok(())
    }

    fn remove_journal_unlocked(&self) -> Result<(), ReleaseError> {
        let path = self.journal_path();
        let metadata = fs::symlink_metadata(&path)?;
        crate::installed_release::validate_private_file_metadata(&metadata)?;
        fs::remove_file(path)?;
        let receipt_path = self.receipt_path();
        let directory = receipt_path
            .parent()
            .expect("the receipt always has a state directory");
        File::open(directory)?.sync_all()?;
        Ok(())
    }
}

impl DebianUpdateJournal {
    fn new(previous: &InstalledReleaseReceipt, candidate: &InstalledReleaseReceipt) -> Self {
        Self {
            schema_version: TRANSACTION_SCHEMA_VERSION,
            previous_release_version: previous.active_release.manifest.release_version.clone(),
            previous_manifest_sha256: previous.active_release.signature.manifest_sha256.clone(),
            previous_artifact: previous.active_artifact.clone(),
            candidate_release_version: candidate.active_release.manifest.release_version.clone(),
            candidate_manifest_sha256: candidate.active_release.signature.manifest_sha256.clone(),
            candidate_artifact: candidate.active_artifact.clone(),
        }
    }

    fn validate(&self) -> Result<(), ReleaseError> {
        if self.schema_version != TRANSACTION_SCHEMA_VERSION
            || !canonical_semver(&self.previous_release_version)
            || !canonical_semver(&self.candidate_release_version)
            || !valid_digest(&self.previous_manifest_sha256)
            || !valid_digest(&self.candidate_manifest_sha256)
            || self.previous_manifest_sha256 == self.candidate_manifest_sha256
            || self.previous_artifact.kind != ArtifactKind::LinuxDeb
            || self.candidate_artifact.kind != ArtifactKind::LinuxDeb
            || self.previous_artifact.target != self.candidate_artifact.target
            || self.previous_artifact.sha256 == self.candidate_artifact.sha256
            || validate_artifact(&self.previous_artifact).is_err()
            || validate_artifact(&self.candidate_artifact).is_err()
        {
            return Err(ReleaseError::InvalidDebianUpdateJournal);
        }
        Ok(())
    }

    fn matches_previous(&self, receipt: &InstalledReleaseReceipt) -> bool {
        receipt.active_release.manifest.release_version == self.previous_release_version
            && receipt.active_release.signature.manifest_sha256 == self.previous_manifest_sha256
            && receipt.active_artifact == self.previous_artifact
    }

    fn matches_candidate(&self, receipt: &InstalledReleaseReceipt) -> bool {
        receipt.active_release.manifest.release_version == self.candidate_release_version
            && receipt.active_release.signature.manifest_sha256 == self.candidate_manifest_sha256
            && receipt.active_artifact == self.candidate_artifact
    }
}

fn require_transaction_support(manifest: &ReleaseManifest) -> Result<(), ReleaseError> {
    let supported = manifest
        .state_compatibility
        .iter()
        .find(|state| state.state == TRANSACTION_STATE_NAME)
        .is_some_and(|state| {
            state.reads.minimum <= TRANSACTION_SCHEMA_VERSION
                && state.reads.maximum >= TRANSACTION_SCHEMA_VERSION
                && state.writes.minimum <= TRANSACTION_SCHEMA_VERSION
                && state.writes.maximum >= TRANSACTION_SCHEMA_VERSION
        });
    if supported {
        Ok(())
    } else {
        Err(ReleaseError::DebianUpdateStateUnsupported)
    }
}

fn cleanup_preflight_failure(
    store: &InstalledReleaseStore,
    current: &InstalledReleaseReceipt,
    error: ReleaseError,
) -> Result<InstallationDecision, ReleaseError> {
    match store.cleanup_cached_artifacts_unlocked(&[&current.active_artifact]) {
        Ok(()) => Err(error),
        Err(cleanup_error) => Err(cleanup_error),
    }
}

fn canonical_semver(value: &str) -> bool {
    Version::parse(value).is_ok_and(|version| version.to_string() == value)
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(feature = "test-release-fault-injection")]
fn test_crash_at(point: &str, exit_code: i32) {
    const POINT_ENVIRONMENT: &str = "SIRINVPN_RELEASE_TEST_CRASH_POINT";
    const CONFIRM_ENVIRONMENT: &str = "SIRINVPN_RELEASE_TEST_CRASH_CONFIRM";
    const CONFIRMATION: &str = "crash-disposable-debian13-vm";

    if std::env::var(CONFIRM_ENVIRONMENT).as_deref() == Ok(CONFIRMATION)
        && std::env::var(POINT_ENVIRONMENT).as_deref() == Ok(point)
    {
        eprintln!("terminating at the disposable-VM release test point: {point}");
        std::process::exit(exit_code);
    }
}

impl DebianPackageManager for SystemDebianPackageManager {
    fn lock_network_operations(&self) -> Result<Box<dyn Send>, ReleaseError> {
        let directory = Path::new(NETWORK_RUNTIME_DIRECTORY);
        match fs::symlink_metadata(directory) {
            Ok(metadata) => validate_network_runtime_directory(&metadata)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let mut builder = fs::DirBuilder::new();
                builder.mode(0o755);
                match builder.create(directory) {
                    Ok(()) => fs::set_permissions(directory, fs::Permissions::from_mode(0o755))
                        .map_err(|_| ReleaseError::DebianPackageOperation)?,
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                    Err(_) => return Err(ReleaseError::DebianPackageOperation),
                }
                validate_network_runtime_directory(
                    &fs::symlink_metadata(directory)
                        .map_err(|_| ReleaseError::DebianPackageOperation)?,
                )?;
            }
            Err(_) => return Err(ReleaseError::DebianPackageOperation),
        }
        let lock_path = Path::new(NETWORK_OPERATION_LOCK);
        let existed = match fs::symlink_metadata(lock_path) {
            Ok(metadata) => {
                validate_network_lock(&metadata)?;
                true
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
            Err(_) => return Err(ReleaseError::DebianPackageOperation),
        };
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(lock_path)
            .map_err(|_| ReleaseError::DebianPackageOperation)?;
        if !existed {
            lock.set_permissions(fs::Permissions::from_mode(0o600))
                .map_err(|_| ReleaseError::DebianPackageOperation)?;
        }
        validate_network_lock(
            &lock
                .metadata()
                .map_err(|_| ReleaseError::DebianPackageOperation)?,
        )?;
        FileExt::lock_exclusive(&lock).map_err(|_| ReleaseError::DebianPackageOperation)?;
        Ok(Box::new(lock))
    }

    fn preflight_candidate(
        &self,
        package: &Path,
        expected_version: &str,
        target: &str,
    ) -> Result<(), ReleaseError> {
        let expected_architecture = match target {
            "x86_64-unknown-linux-gnu" => "amd64",
            "aarch64-unknown-linux-gnu" => "arm64",
            _ => return Err(ReleaseError::InvalidDebianPackage),
        };
        let package_name = debian_control_field(package, "Package")?;
        let package_version = debian_control_field(package, "Version")?;
        let package_architecture = debian_control_field(package, "Architecture")?;
        if package_name != DEBIAN_PACKAGE_NAME
            || package_version != expected_version
            || package_architecture != expected_architecture
        {
            return Err(ReleaseError::InvalidDebianPackage);
        }
        Ok(())
    }

    fn install_package(&self, package: &Path, _expected_version: &str) -> Result<(), ReleaseError> {
        let status = sanitized_command(DPKG_PATH)
            .arg("--install")
            .arg(package)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map_err(|_| ReleaseError::DebianPackageOperation)?;
        if status.success() {
            Ok(())
        } else {
            Err(ReleaseError::DebianPackageOperation)
        }
    }

    fn check_installed_health(&self, expected_version: &str) -> Result<(), ReleaseError> {
        match fs::symlink_metadata(PERSISTENT_CONNECTION_PATH) {
            Ok(_) => return Err(ReleaseError::DebianUpdateTunnelActive),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(ReleaseError::DebianPackageHealth),
        }
        let status = command_output(
            sanitized_command(DPKG_QUERY_PATH)
                .arg("--show")
                .arg("--showformat=${db:Status-Abbrev}\t${Version}\n")
                .arg(DEBIAN_PACKAGE_NAME),
            CommandFailure::Health,
        )?;
        let status = std::str::from_utf8(&status).map_err(|_| ReleaseError::DebianPackageHealth)?;
        let (abbreviation, version) = status
            .strip_suffix('\n')
            .and_then(|line| line.split_once('\t'))
            .ok_or(ReleaseError::DebianPackageHealth)?;
        if abbreviation != "ii " || version != expected_version {
            return Err(ReleaseError::DebianPackageHealth);
        }

        let verification = command_output(
            sanitized_command(DPKG_PATH)
                .arg("--verify")
                .arg(DEBIAN_PACKAGE_NAME),
            CommandFailure::Health,
        )?;
        if !verification.is_empty() {
            return Err(ReleaseError::DebianPackageHealth);
        }
        for path in INSTALLED_EXECUTABLES {
            validate_installed_executable(Path::new(path))?;
        }

        let release_version = command_output(
            sanitized_command(RELEASE_TOOL_PATH).arg("--version"),
            CommandFailure::Health,
        )?;
        let release_version =
            std::str::from_utf8(&release_version).map_err(|_| ReleaseError::DebianPackageHealth)?;
        if release_version.trim_end() != format!("sirinvpn-release {expected_version}") {
            return Err(ReleaseError::DebianPackageHealth);
        }

        let helper_status = command_output(
            sanitized_command(HELPER_PATH).arg("status"),
            CommandFailure::Health,
        )?;
        let helper_status: serde_json::Value = serde_json::from_slice(&helper_status)
            .map_err(|_| ReleaseError::DebianPackageHealth)?;
        if helper_status.get("state").and_then(|value| value.as_str()) != Some("disconnected")
            || helper_status
                .get("kill_switch_enabled")
                .and_then(|value| value.as_bool())
                != Some(false)
            || helper_status
                .get("auto_reconnect_enabled")
                .and_then(|value| value.as_bool())
                != Some(false)
        {
            return Err(ReleaseError::DebianUpdateTunnelActive);
        }
        Ok(())
    }
}

fn debian_control_field(package: &Path, field: &str) -> Result<String, ReleaseError> {
    let output = command_output(
        sanitized_command(DPKG_DEB_PATH)
            .arg("--field")
            .arg(package)
            .arg(field),
        CommandFailure::InvalidPackage,
    )?;
    let value = std::str::from_utf8(&output)
        .map_err(|_| ReleaseError::InvalidDebianPackage)?
        .trim_end_matches('\n');
    if value.is_empty() || value.contains('\n') || value.contains('\r') {
        return Err(ReleaseError::InvalidDebianPackage);
    }
    Ok(value.to_owned())
}

fn validate_installed_executable(path: &Path) -> Result<(), ReleaseError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| ReleaseError::DebianPackageHealth)?;
    if !metadata.file_type().is_file()
        || metadata.uid() != 0
        || metadata.nlink() != 1
        || metadata.mode() & 0o111 == 0
        || metadata.mode() & 0o022 != 0
    {
        return Err(ReleaseError::DebianPackageHealth);
    }
    Ok(())
}

fn validate_network_runtime_directory(metadata: &fs::Metadata) -> Result<(), ReleaseError> {
    if !metadata.file_type().is_dir() || metadata.uid() != 0 || metadata.mode() & 0o777 != 0o755 {
        return Err(ReleaseError::DebianPackageOperation);
    }
    Ok(())
}

fn validate_network_lock(metadata: &fs::Metadata) -> Result<(), ReleaseError> {
    if !metadata.file_type().is_file()
        || metadata.uid() != 0
        || metadata.mode() & 0o777 != 0o600
        || metadata.nlink() != 1
    {
        return Err(ReleaseError::DebianPackageOperation);
    }
    Ok(())
}

fn sanitized_command(program: &str) -> Command {
    let mut command = Command::new(program);
    command
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .env("LANG", "C.UTF-8")
        .env("LC_ALL", "C.UTF-8")
        .env("DEBIAN_FRONTEND", "noninteractive")
        .stdin(Stdio::null())
        .stderr(Stdio::null());
    command
}

fn command_output(command: &mut Command, failure: CommandFailure) -> Result<Vec<u8>, ReleaseError> {
    let output = command
        .stdout(Stdio::piped())
        .output()
        .map_err(|_| failure.error())?;
    if !output.status.success() || output.stdout.len() > MAX_COMMAND_OUTPUT_BYTES {
        return Err(failure.error());
    }
    Ok(output.stdout)
}

#[cfg(test)]
mod tests;
