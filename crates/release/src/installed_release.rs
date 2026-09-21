mod compatibility;
mod file_access;
use compatibility::plan_artifact_transition;

use crate::{
    ArtifactKind, INSTALLED_RELEASE_RECEIPT_SCHEMA_VERSION, ReleaseArtifact, ReleaseChannel,
    ReleaseError, ReleaseManifest, ReleaseSignature, UpdateDirection, canonical_json,
    canonical_public_key_pem, digest_artifact, encode_manifest, encode_signature, parse_signature,
    plan_transition, validate_artifact, verify_manifest, verify_release_artifact,
    verify_release_artifact_with_trust_policy,
};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use sirinvpn_platform::files;
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
use std::{
    cmp::Ordering,
    fs::{self, File},
    io::Read,
    path::{Path, PathBuf},
};

pub const SYSTEM_RELEASE_STATE_DIRECTORY: &str = "/var/lib/sirinvpn-release";

const RECEIPT_FILE_NAME: &str = "receipt.json";
const LOCK_FILE_NAME: &str = "receipt.lock";
const PACKAGE_DIRECTORY_NAME: &str = "packages";
const MAX_RECEIPT_BYTES: u64 = 768 * 1024;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedReleaseRecord {
    pub manifest: ReleaseManifest,
    pub signature: ReleaseSignature,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstalledReleaseReceipt {
    pub schema_version: u16,
    pub trusted_public_key_pem: String,
    pub active_release: SignedReleaseRecord,
    pub active_artifact: ReleaseArtifact,
    pub highest_accepted_release: SignedReleaseRecord,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InstallationDecisionKind {
    Initialize,
    Upgrade,
    Rollback,
    Rebind,
    AlreadyBound,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct InstalledReleaseSummary {
    pub schema_version: u16,
    pub channel: ReleaseChannel,
    pub active_release_version: String,
    pub active_release_sequence: u64,
    pub active_manifest_sha256: String,
    pub active_artifact: ReleaseArtifact,
    pub highest_accepted_release_version: String,
    pub highest_accepted_release_sequence: u64,
    pub highest_accepted_manifest_sha256: String,
    pub key_id_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct InstallationDecision {
    pub action: InstallationDecisionKind,
    pub state: InstalledReleaseSummary,
}

#[derive(Clone, Debug)]
pub struct InstalledReleaseStore {
    directory: PathBuf,
    #[cfg(windows)]
    administrator_owned: bool,
}

pub(crate) struct VerifiedCandidate {
    pub(crate) release: SignedReleaseRecord,
    pub(crate) artifact: ReleaseArtifact,
}

impl InstalledReleaseStore {
    pub fn new(directory: impl Into<PathBuf>) -> Self {
        Self {
            directory: directory.into(),
            #[cfg(windows)]
            administrator_owned: false,
        }
    }

    pub fn system() -> Self {
        Self::new(SYSTEM_RELEASE_STATE_DIRECTORY)
    }

    pub fn inspect(&self) -> Result<Option<InstalledReleaseSummary>, ReleaseError> {
        if !self.validate_existing_directory()? {
            return Ok(None);
        }
        let lock = self.open_lock()?;
        FileExt::lock_shared(&lock)?;
        let result = self
            .read_receipt_unlocked()
            .map(|receipt| receipt.map(|value| summarize(&value)));
        finish_locked(lock, result)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn plan_installation(
        &self,
        manifest_bytes: &[u8],
        signature_bytes: &[u8],
        trusted_public_key_pem: &str,
        artifact_directory: &Path,
        artifact_kind: ArtifactKind,
        artifact_target: &str,
        allow_rollback: bool,
    ) -> Result<InstallationDecision, ReleaseError> {
        let (candidate, canonical_key) = verify_candidate(
            manifest_bytes,
            signature_bytes,
            trusted_public_key_pem,
            artifact_directory,
            artifact_kind,
            artifact_target,
        )?;
        if !self.validate_existing_directory()? {
            let (receipt, action) = evaluate(None, candidate, canonical_key, allow_rollback)?;
            return Ok(decision(action, &receipt));
        }
        let lock = self.open_lock()?;
        FileExt::lock_shared(&lock)?;
        let result = (|| {
            if self.trust_entry_exists_unlocked()? {
                return Err(ReleaseError::InstalledTrustForbidsExplicitKey);
            }
            let current = self.read_receipt_unlocked()?;
            let (receipt, action) = evaluate(current, candidate, canonical_key, allow_rollback)?;
            Ok(decision(action, &receipt))
        })();
        finish_locked(lock, result)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn commit_installation(
        &self,
        manifest_bytes: &[u8],
        signature_bytes: &[u8],
        trusted_public_key_pem: &str,
        artifact_directory: &Path,
        artifact_kind: ArtifactKind,
        artifact_target: &str,
        allow_rollback: bool,
    ) -> Result<InstallationDecision, ReleaseError> {
        let (candidate, canonical_key) = verify_candidate(
            manifest_bytes,
            signature_bytes,
            trusted_public_key_pem,
            artifact_directory,
            artifact_kind,
            artifact_target,
        )?;
        self.ensure_directory()?;
        let lock = self.open_lock()?;
        FileExt::lock_exclusive(&lock)?;
        let result = (|| {
            if self.trust_entry_exists_unlocked()? {
                return Err(ReleaseError::InstalledTrustForbidsExplicitKey);
            }
            let current = self.read_receipt_unlocked()?;
            let (receipt, action) = evaluate(current, candidate, canonical_key, allow_rollback)?;
            self.cache_artifact_unlocked(artifact_directory, &receipt.active_artifact)?;
            if action != InstallationDecisionKind::AlreadyBound {
                self.write_receipt_unlocked(&receipt)?;
            }
            self.cleanup_cached_artifacts_unlocked(&[&receipt.active_artifact])?;
            Ok(decision(action, &receipt))
        })();
        finish_locked(lock, result)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn plan_trusted_installation(
        &self,
        manifest_bytes: &[u8],
        signature_bytes: &[u8],
        artifact_directory: &Path,
        artifact_kind: ArtifactKind,
        artifact_target: &str,
        allow_rollback: bool,
    ) -> Result<InstallationDecision, ReleaseError> {
        self.plan_trusted_installation_with_root(
            manifest_bytes,
            signature_bytes,
            artifact_directory,
            artifact_kind,
            artifact_target,
            allow_rollback,
            crate::BUNDLED_RELEASE_TRUST_ROOT_PEM,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn plan_trusted_installation_with_root(
        &self,
        manifest_bytes: &[u8],
        signature_bytes: &[u8],
        artifact_directory: &Path,
        artifact_kind: ArtifactKind,
        artifact_target: &str,
        allow_rollback: bool,
        root_public_key_pem: &str,
    ) -> Result<InstallationDecision, ReleaseError> {
        if !self.validate_existing_directory()? {
            return Err(ReleaseError::InstalledTrustRequired);
        }
        let lock = self.open_lock()?;
        FileExt::lock_shared(&lock)?;
        let result = (|| {
            let trust = self
                .read_trust_unlocked_with_root(root_public_key_pem)?
                .ok_or(ReleaseError::InstalledTrustRequired)?;
            let verified_trust = crate::trust::verify_installed_trust(&trust, root_public_key_pem)?;
            let (candidate, canonical_key) = verify_candidate_with_trust(
                manifest_bytes,
                signature_bytes,
                &verified_trust,
                artifact_directory,
                artifact_kind,
                artifact_target,
            )?;
            let current = self.read_receipt_unlocked()?;
            let (receipt, action) = evaluate_with_key_transition(
                current,
                candidate,
                canonical_key,
                allow_rollback,
                true,
            )?;
            Ok(decision(action, &receipt))
        })();
        finish_locked(lock, result)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn commit_trusted_installation(
        &self,
        manifest_bytes: &[u8],
        signature_bytes: &[u8],
        artifact_directory: &Path,
        artifact_kind: ArtifactKind,
        artifact_target: &str,
        allow_rollback: bool,
    ) -> Result<InstallationDecision, ReleaseError> {
        self.commit_trusted_installation_with_root(
            manifest_bytes,
            signature_bytes,
            artifact_directory,
            artifact_kind,
            artifact_target,
            allow_rollback,
            crate::BUNDLED_RELEASE_TRUST_ROOT_PEM,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn commit_trusted_installation_with_root(
        &self,
        manifest_bytes: &[u8],
        signature_bytes: &[u8],
        artifact_directory: &Path,
        artifact_kind: ArtifactKind,
        artifact_target: &str,
        allow_rollback: bool,
        root_public_key_pem: &str,
    ) -> Result<InstallationDecision, ReleaseError> {
        if !self.validate_existing_directory()? {
            return Err(ReleaseError::InstalledTrustRequired);
        }
        let lock = self.open_lock()?;
        FileExt::lock_exclusive(&lock)?;
        let result = (|| {
            let trust = self
                .read_trust_unlocked_with_root(root_public_key_pem)?
                .ok_or(ReleaseError::InstalledTrustRequired)?;
            let verified_trust = crate::trust::verify_installed_trust(&trust, root_public_key_pem)?;
            let (candidate, canonical_key) = verify_candidate_with_trust(
                manifest_bytes,
                signature_bytes,
                &verified_trust,
                artifact_directory,
                artifact_kind,
                artifact_target,
            )?;
            let current = self.read_receipt_unlocked()?;
            let (receipt, action) = evaluate_with_key_transition(
                current,
                candidate,
                canonical_key,
                allow_rollback,
                true,
            )?;
            self.cache_artifact_unlocked(artifact_directory, &receipt.active_artifact)?;
            if action != InstallationDecisionKind::AlreadyBound {
                self.write_receipt_unlocked(&receipt)?;
            }
            self.cleanup_cached_artifacts_unlocked(&[&receipt.active_artifact])?;
            Ok(decision(action, &receipt))
        })();
        finish_locked(lock, result)
    }

    pub(crate) fn state_directory(&self) -> &Path {
        &self.directory
    }

    pub(crate) fn receipt_path(&self) -> PathBuf {
        self.directory.join(RECEIPT_FILE_NAME)
    }

    pub(crate) fn lock_path(&self) -> PathBuf {
        self.directory.join(LOCK_FILE_NAME)
    }

    pub(crate) fn package_directory(&self) -> PathBuf {
        self.directory.join(PACKAGE_DIRECTORY_NAME)
    }

    pub(crate) fn validate_existing_directory(&self) -> Result<bool, ReleaseError> {
        let metadata = match fs::symlink_metadata(&self.directory) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(error.into()),
        };
        validate_directory_metadata(&metadata)?;
        self.validate_state_directory(&self.directory)?;
        Ok(true)
    }

    pub(crate) fn ensure_directory(&self) -> Result<(), ReleaseError> {
        if self.validate_existing_directory()? {
            return Ok(());
        }
        self.create_state_directory(&self.directory)?;
        let metadata = fs::symlink_metadata(&self.directory)?;
        validate_directory_metadata(&metadata)?;
        let parent = self
            .directory
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        files::sync_directory(parent)?;
        Ok(())
    }

    pub(crate) fn open_lock(&self) -> Result<File, ReleaseError> {
        let path = self.lock_path();
        match fs::symlink_metadata(&path) {
            Ok(metadata) => {
                validate_private_file_metadata(&metadata)?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
            Err(error) => return Err(error.into()),
        };
        let file = self.open_state_lock(&path)?;
        self.validate_state_file(&file)?;
        validate_private_file_metadata(&file.metadata()?)?;
        Ok(file)
    }

    pub(crate) fn read_receipt_unlocked(
        &self,
    ) -> Result<Option<InstalledReleaseReceipt>, ReleaseError> {
        let path = self.receipt_path();
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        validate_private_file_metadata(&metadata)?;
        if metadata.len() == 0 || metadata.len() > MAX_RECEIPT_BYTES {
            return Err(ReleaseError::InstalledReceiptSize);
        }
        let file = files::open_no_follow(&path)?;
        self.validate_state_file(&file)?;
        validate_private_file_metadata(&file.metadata()?)?;
        let mut bytes = Vec::with_capacity(metadata.len() as usize);
        file.take(MAX_RECEIPT_BYTES + 1).read_to_end(&mut bytes)?;
        let receipt = parse_receipt(&bytes)?;
        self.validate_cached_artifact_unlocked(&receipt.active_artifact)?;
        Ok(Some(receipt))
    }

    pub(crate) fn write_receipt_unlocked(
        &self,
        receipt: &InstalledReleaseReceipt,
    ) -> Result<(), ReleaseError> {
        validate_receipt(receipt)?;
        let bytes = canonical_json(receipt)?;
        if bytes.len() as u64 > MAX_RECEIPT_BYTES {
            return Err(ReleaseError::InstalledReceiptSize);
        }
        self.write_state(&self.receipt_path(), &bytes)?;
        Ok(())
    }

    pub(crate) fn cache_artifact_unlocked(
        &self,
        artifact_directory: &Path,
        artifact: &ReleaseArtifact,
    ) -> Result<PathBuf, ReleaseError> {
        validate_artifact(artifact)?;
        self.ensure_package_directory()?;
        let cached_path = self.cached_artifact_path(artifact)?;
        match fs::symlink_metadata(&cached_path) {
            Ok(_) => {
                self.validate_cached_artifact_unlocked(artifact)?;
                return Ok(cached_path);
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }

        let source_path = artifact_directory.join(&artifact.file_name);
        let source = files::open_no_follow(&source_path)
            .map_err(|_| ReleaseError::InvalidArtifact(artifact.file_name.clone()))?;
        let metadata = source
            .metadata()
            .map_err(|_| ReleaseError::InvalidArtifact(artifact.file_name.clone()))?;
        if !metadata.file_type().is_file() || metadata.len() != artifact.size_bytes {
            return Err(ReleaseError::ArtifactSizeMismatch(
                artifact.file_name.clone(),
            ));
        }

        let package_directory = self.package_directory();
        let mut temporary = self.temporary_state_file(&package_directory, ".package-")?;
        let copied = std::io::copy(
            &mut source.take(crate::MAX_ARTIFACT_BYTES + 1),
            temporary.as_file_mut(),
        )?;
        if copied != artifact.size_bytes {
            return Err(ReleaseError::ArtifactSizeMismatch(
                artifact.file_name.clone(),
            ));
        }
        temporary.as_file().sync_all()?;
        let (cached_size, cached_digest) = digest_artifact(temporary.path())?;
        if cached_size != artifact.size_bytes {
            return Err(ReleaseError::ArtifactSizeMismatch(
                artifact.file_name.clone(),
            ));
        }
        if cached_digest != artifact.sha256 {
            return Err(ReleaseError::ArtifactDigestMismatch(
                artifact.file_name.clone(),
            ));
        }
        match files::persist(temporary, &cached_path, false) {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                self.validate_cached_artifact_unlocked(artifact)?;
            }
            Err(error) => return Err(error.into()),
        }
        files::sync_directory(&package_directory)?;
        Ok(cached_path)
    }

    pub(crate) fn cached_artifact_path(
        &self,
        artifact: &ReleaseArtifact,
    ) -> Result<PathBuf, ReleaseError> {
        validate_artifact(artifact)?;
        let suffix = match artifact.kind {
            ArtifactKind::LinuxDeb => "deb",
            ArtifactKind::LinuxAppImage => "AppImage",
            ArtifactKind::ServerElf => "server",
            ArtifactKind::WindowsInstaller => "exe",
            ArtifactKind::AndroidApk => "apk",
        };
        Ok(self
            .package_directory()
            .join(format!("{}.{}", artifact.sha256, suffix)))
    }

    pub(crate) fn validate_cached_artifact_unlocked(
        &self,
        artifact: &ReleaseArtifact,
    ) -> Result<PathBuf, ReleaseError> {
        let package_directory = self.package_directory();
        let directory_metadata = fs::symlink_metadata(&package_directory)
            .map_err(|_| ReleaseError::InstalledPackageCacheMissing)?;
        validate_directory_metadata(&directory_metadata)?;
        self.validate_state_directory(&package_directory)?;
        let path = self.cached_artifact_path(artifact)?;
        let metadata =
            fs::symlink_metadata(&path).map_err(|_| ReleaseError::InstalledPackageCacheMissing)?;
        validate_private_file_metadata(&metadata)?;
        self.validate_state_file(&files::open_no_follow(&path)?)?;
        let (size, digest) = digest_artifact(&path)?;
        if size != artifact.size_bytes || digest != artifact.sha256 {
            return Err(ReleaseError::InvalidInstalledPackageCache);
        }
        Ok(path)
    }

    pub(crate) fn cleanup_cached_artifacts_unlocked(
        &self,
        retained: &[&ReleaseArtifact],
    ) -> Result<(), ReleaseError> {
        let package_directory = self.package_directory();
        let metadata = match fs::symlink_metadata(&package_directory) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error.into()),
        };
        validate_directory_metadata(&metadata)?;
        self.validate_state_directory(&package_directory)?;
        let retained = retained
            .iter()
            .map(|artifact| self.cached_artifact_path(artifact))
            .collect::<Result<Vec<_>, _>>()?;
        for entry in fs::read_dir(&package_directory)? {
            let entry = entry?;
            let path = entry.path();
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| ReleaseError::UnsafeInstalledState)?;
            if name.starts_with(".package-") {
                let entry_metadata = fs::symlink_metadata(&path)?;
                validate_private_file_metadata(&entry_metadata)?;
                self.validate_state_file(&files::open_no_follow(&path)?)?;
                fs::remove_file(path)?;
                continue;
            }
            if !is_package_cache_name(&name) {
                return Err(ReleaseError::UnsafeInstalledState);
            }
            let entry_metadata = fs::symlink_metadata(&path)?;
            validate_private_file_metadata(&entry_metadata)?;
            self.validate_state_file(&files::open_no_follow(&path)?)?;
            if !retained.iter().any(|retained_path| retained_path == &path) {
                fs::remove_file(path)?;
            }
        }
        files::sync_directory(&package_directory)?;
        Ok(())
    }

    fn ensure_package_directory(&self) -> Result<(), ReleaseError> {
        let path = self.package_directory();
        match fs::symlink_metadata(&path) {
            Ok(metadata) => {
                validate_directory_metadata(&metadata)?;
                self.validate_state_directory(&path)?;
                return Ok(());
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        self.create_state_directory(&path)?;
        validate_directory_metadata(&fs::symlink_metadata(&path)?)?;
        files::sync_directory(&self.directory)?;
        Ok(())
    }
}

pub(crate) fn verify_candidate(
    manifest_bytes: &[u8],
    signature_bytes: &[u8],
    trusted_public_key_pem: &str,
    artifact_directory: &Path,
    artifact_kind: ArtifactKind,
    artifact_target: &str,
) -> Result<(VerifiedCandidate, String), ReleaseError> {
    if !matches!(
        artifact_kind,
        ArtifactKind::LinuxAppImage
            | ArtifactKind::LinuxDeb
            | ArtifactKind::AndroidApk
            | ArtifactKind::ServerElf
            | ArtifactKind::WindowsInstaller
    ) {
        return Err(ReleaseError::InstalledArtifactUnsupported);
    }
    let canonical_key = canonical_public_key_pem(trusted_public_key_pem)?;
    let verified = verify_release_artifact(
        manifest_bytes,
        signature_bytes,
        &canonical_key,
        artifact_directory,
        artifact_kind,
        artifact_target,
    )?;
    require_receipt_schema_support(&verified.manifest)?;
    let signature = parse_signature(signature_bytes)?;
    Ok((
        VerifiedCandidate {
            release: SignedReleaseRecord {
                manifest: verified.manifest,
                signature,
            },
            artifact: verified.artifact,
        },
        canonical_key,
    ))
}

pub(crate) fn verify_candidate_with_trust(
    manifest_bytes: &[u8],
    signature_bytes: &[u8],
    trust: &crate::VerifiedReleaseTrustPolicy,
    artifact_directory: &Path,
    artifact_kind: ArtifactKind,
    artifact_target: &str,
) -> Result<(VerifiedCandidate, String), ReleaseError> {
    if !matches!(
        artifact_kind,
        ArtifactKind::LinuxAppImage
            | ArtifactKind::LinuxDeb
            | ArtifactKind::AndroidApk
            | ArtifactKind::ServerElf
            | ArtifactKind::WindowsInstaller
    ) {
        return Err(ReleaseError::InstalledArtifactUnsupported);
    }
    let verified = verify_release_artifact_with_trust_policy(
        manifest_bytes,
        signature_bytes,
        trust,
        artifact_directory,
        artifact_kind,
        artifact_target,
    )?;
    require_receipt_schema_support(&verified.manifest)?;
    require_trust_schema_support(&verified.manifest)?;
    let signature = parse_signature(signature_bytes)?;
    let canonical_key = trust
        .policy
        .active_release_keys
        .iter()
        .find(|key| key.key_id_sha256 == signature.key_id_sha256)
        .map(|key| key.public_key_pem.clone())
        .ok_or(ReleaseError::ReleaseKeyNotTrusted)?;
    Ok((
        VerifiedCandidate {
            release: SignedReleaseRecord {
                manifest: verified.manifest,
                signature,
            },
            artifact: verified.artifact,
        },
        canonical_key,
    ))
}

pub(crate) fn evaluate(
    current: Option<InstalledReleaseReceipt>,
    candidate: VerifiedCandidate,
    canonical_key: String,
    allow_rollback: bool,
) -> Result<(InstalledReleaseReceipt, InstallationDecisionKind), ReleaseError> {
    evaluate_with_key_transition(current, candidate, canonical_key, allow_rollback, false)
}

pub(crate) fn evaluate_with_key_transition(
    current: Option<InstalledReleaseReceipt>,
    candidate: VerifiedCandidate,
    canonical_key: String,
    allow_rollback: bool,
    allow_key_transition: bool,
) -> Result<(InstalledReleaseReceipt, InstallationDecisionKind), ReleaseError> {
    let Some(mut receipt) = current else {
        let release = candidate.release;
        return Ok((
            InstalledReleaseReceipt {
                schema_version: INSTALLED_RELEASE_RECEIPT_SCHEMA_VERSION,
                trusted_public_key_pem: canonical_key,
                active_release: release.clone(),
                active_artifact: candidate.artifact,
                highest_accepted_release: release,
            },
            InstallationDecisionKind::Initialize,
        ));
    };

    validate_receipt(&receipt)?;
    let key_changed = receipt.trusted_public_key_pem != canonical_key;
    if key_changed && !allow_key_transition {
        return Err(ReleaseError::KeyIdMismatch);
    }

    let candidate_digest = &candidate.release.signature.manifest_sha256;
    let active_digest = &receipt.active_release.signature.manifest_sha256;
    let highest_digest = &receipt.highest_accepted_release.signature.manifest_sha256;
    let candidate_sequence = candidate.release.manifest.release_sequence;
    let active_sequence = receipt.active_release.manifest.release_sequence;
    let highest_sequence = receipt.highest_accepted_release.manifest.release_sequence;

    if candidate_sequence == active_sequence && candidate_digest != active_digest
        || candidate_sequence == highest_sequence && candidate_digest != highest_digest
    {
        return Err(ReleaseError::ReleaseSequenceCollision);
    }

    if candidate_digest == active_digest {
        if key_changed {
            return Err(ReleaseError::ReleaseKeyTransitionRequiresUpgrade);
        }
        if candidate.release.manifest != receipt.active_release.manifest {
            return Err(ReleaseError::ReleaseSequenceCollision);
        }
        let action = if candidate.artifact == receipt.active_artifact {
            InstallationDecisionKind::AlreadyBound
        } else {
            InstallationDecisionKind::Rebind
        };
        receipt.active_release = candidate.release;
        receipt.active_artifact = candidate.artifact;
        return Ok((receipt, action));
    }

    let transition = plan_artifact_transition(
        &receipt.active_release.manifest,
        &candidate.release.manifest,
        candidate.artifact.kind,
        allow_rollback,
    )?;
    let action = match transition.direction {
        UpdateDirection::Rollback => {
            if key_changed {
                return Err(ReleaseError::ReleaseKeyTransitionRequiresUpgrade);
            }
            InstallationDecisionKind::Rollback
        }
        UpdateDirection::Upgrade => {
            if key_changed && candidate_sequence <= highest_sequence {
                return Err(ReleaseError::ReleaseKeyTransitionRequiresUpgrade);
            }
            match candidate_sequence.cmp(&highest_sequence) {
                Ordering::Less => return Err(ReleaseError::BelowHighestAcceptedRelease),
                Ordering::Equal => {
                    if candidate.release != receipt.highest_accepted_release {
                        return Err(ReleaseError::ReleaseSequenceCollision);
                    }
                }
                Ordering::Greater => {
                    plan_artifact_transition(
                        &receipt.highest_accepted_release.manifest,
                        &candidate.release.manifest,
                        candidate.artifact.kind,
                        false,
                    )?;
                    receipt.highest_accepted_release = candidate.release.clone();
                }
            }
            InstallationDecisionKind::Upgrade
        }
    };
    if key_changed {
        receipt.trusted_public_key_pem = canonical_key;
    }
    receipt.active_release = candidate.release;
    receipt.active_artifact = candidate.artifact;
    validate_receipt(&receipt)?;
    Ok((receipt, action))
}

/// Validate a receipt's canonical encoding, signatures and transition history.
/// Its recorded key is trusted only when the caller obtained the receipt from
/// the protected installed state, such as an authenticated root SSH read.
pub fn parse_receipt(bytes: &[u8]) -> Result<InstalledReleaseReceipt, ReleaseError> {
    if bytes.is_empty() || bytes.len() as u64 > MAX_RECEIPT_BYTES {
        return Err(ReleaseError::InstalledReceiptSize);
    }
    let receipt: InstalledReleaseReceipt =
        serde_json::from_slice(bytes).map_err(|_| ReleaseError::InvalidInstalledReceipt)?;
    validate_receipt(&receipt)?;
    if canonical_json(&receipt)? != bytes {
        return Err(ReleaseError::NonCanonicalInstalledReceipt);
    }
    Ok(receipt)
}

pub(crate) fn validate_receipt(receipt: &InstalledReleaseReceipt) -> Result<(), ReleaseError> {
    if receipt.schema_version != INSTALLED_RELEASE_RECEIPT_SCHEMA_VERSION {
        return Err(ReleaseError::InvalidInstalledReceipt);
    }
    let canonical_key = canonical_public_key_pem(&receipt.trusted_public_key_pem)
        .map_err(|_| ReleaseError::InvalidInstalledReceipt)?;
    if canonical_key != receipt.trusted_public_key_pem {
        return Err(ReleaseError::InvalidInstalledReceipt);
    }
    let active = verify_record(&receipt.active_release, &canonical_key)
        .map_err(|_| ReleaseError::InvalidInstalledReceipt)?;
    let highest = verify_record(&receipt.highest_accepted_release, &canonical_key)
        .map_err(|_| ReleaseError::InvalidInstalledReceipt)?;
    require_receipt_schema_support(&active.manifest)
        .map_err(|_| ReleaseError::InvalidInstalledReceipt)?;
    require_receipt_schema_support(&highest.manifest)
        .map_err(|_| ReleaseError::InvalidInstalledReceipt)?;
    if !receipt
        .active_release
        .manifest
        .artifacts
        .iter()
        .any(|artifact| artifact == &receipt.active_artifact)
    {
        return Err(ReleaseError::InvalidInstalledReceipt);
    }
    match active
        .manifest
        .release_sequence
        .cmp(&highest.manifest.release_sequence)
    {
        Ordering::Equal => {
            if receipt.active_release != receipt.highest_accepted_release {
                return Err(ReleaseError::InvalidInstalledReceipt);
            }
        }
        Ordering::Less => {
            plan_artifact_transition(
                &active.manifest,
                &highest.manifest,
                receipt.active_artifact.kind,
                false,
            )
            .map_err(|_| ReleaseError::InvalidInstalledReceipt)?;
        }
        Ordering::Greater => return Err(ReleaseError::InvalidInstalledReceipt),
    }
    Ok(())
}

fn verify_record(
    record: &SignedReleaseRecord,
    trusted_public_key_pem: &str,
) -> Result<crate::VerifiedManifest, ReleaseError> {
    let manifest = encode_manifest(&record.manifest)?;
    let signature = encode_signature(&record.signature)?;
    verify_manifest(&manifest, &signature, trusted_public_key_pem)
}

fn require_receipt_schema_support(manifest: &ReleaseManifest) -> Result<(), ReleaseError> {
    let supported = manifest
        .state_compatibility
        .iter()
        .find(|state| state.state == "linux_release_receipt")
        .is_some_and(|state| {
            state.reads.minimum <= INSTALLED_RELEASE_RECEIPT_SCHEMA_VERSION
                && state.reads.maximum >= INSTALLED_RELEASE_RECEIPT_SCHEMA_VERSION
        });
    if supported {
        Ok(())
    } else {
        Err(ReleaseError::InstalledReceiptUnsupported)
    }
}

pub(crate) fn require_trust_schema_support(manifest: &ReleaseManifest) -> Result<(), ReleaseError> {
    let supported = manifest
        .state_compatibility
        .iter()
        .find(|state| state.state == crate::LINUX_RELEASE_TRUST_STATE_NAME)
        .is_some_and(|state| {
            state.reads.minimum <= crate::INSTALLED_RELEASE_TRUST_SCHEMA_VERSION
                && state.reads.maximum >= crate::INSTALLED_RELEASE_TRUST_SCHEMA_VERSION
                && state.writes.minimum <= crate::INSTALLED_RELEASE_TRUST_SCHEMA_VERSION
                && state.writes.maximum >= crate::INSTALLED_RELEASE_TRUST_SCHEMA_VERSION
        });
    if supported {
        Ok(())
    } else {
        Err(ReleaseError::InstalledTrustUnsupported)
    }
}

pub(crate) fn summarize(receipt: &InstalledReleaseReceipt) -> InstalledReleaseSummary {
    InstalledReleaseSummary {
        schema_version: receipt.schema_version,
        channel: receipt.active_release.manifest.channel,
        active_release_version: receipt.active_release.manifest.release_version.clone(),
        active_release_sequence: receipt.active_release.manifest.release_sequence,
        active_manifest_sha256: receipt.active_release.signature.manifest_sha256.clone(),
        active_artifact: receipt.active_artifact.clone(),
        highest_accepted_release_version: receipt
            .highest_accepted_release
            .manifest
            .release_version
            .clone(),
        highest_accepted_release_sequence: receipt
            .highest_accepted_release
            .manifest
            .release_sequence,
        highest_accepted_manifest_sha256: receipt
            .highest_accepted_release
            .signature
            .manifest_sha256
            .clone(),
        key_id_sha256: receipt.active_release.signature.key_id_sha256.clone(),
    }
}

pub(crate) fn decision(
    action: InstallationDecisionKind,
    receipt: &InstalledReleaseReceipt,
) -> InstallationDecision {
    InstallationDecision {
        action,
        state: summarize(receipt),
    }
}

pub(crate) fn validate_directory_metadata(metadata: &fs::Metadata) -> Result<(), ReleaseError> {
    if !metadata.file_type().is_dir() {
        return Err(ReleaseError::UnsafeInstalledState);
    }
    #[cfg(unix)]
    if metadata.uid() != nix::unistd::Uid::effective().as_raw() || metadata.mode() & 0o777 != 0o700
    {
        return Err(ReleaseError::UnsafeInstalledState);
    }
    Ok(())
}

pub(crate) fn validate_private_file_metadata(metadata: &fs::Metadata) -> Result<(), ReleaseError> {
    if !metadata.file_type().is_file() {
        return Err(ReleaseError::UnsafeInstalledState);
    }
    #[cfg(unix)]
    if metadata.uid() != nix::unistd::Uid::effective().as_raw()
        || metadata.mode() & 0o777 != 0o600
        || metadata.nlink() != 1
    {
        return Err(ReleaseError::UnsafeInstalledState);
    }
    Ok(())
}

fn is_package_cache_name(name: &str) -> bool {
    let Some((digest, suffix)) = name.rsplit_once('.') else {
        return false;
    };
    digest.len() == 64
        && digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        && matches!(suffix, "deb" | "AppImage" | "server" | "exe" | "apk")
}

pub(crate) fn finish_locked<T>(
    lock: File,
    result: Result<T, ReleaseError>,
) -> Result<T, ReleaseError> {
    let unlock_result = FileExt::unlock(&lock).map_err(ReleaseError::from);
    match result {
        Err(error) => Err(error),
        Ok(value) => {
            unlock_result?;
            Ok(value)
        }
    }
}

#[cfg(test)]
mod tests;
