#![forbid(unsafe_code)]

#[cfg(target_os = "linux")]
mod appimage_file;
mod client_update;
mod installed_release;
#[cfg(unix)]
mod linux_debian_update;
mod server_update;
mod trust;

pub use server_update::{
    ServerRecoveryAction, ServerReleaseBundle, ServerReleaseHost, ServerReleaseStatus,
};

#[cfg(target_os = "linux")]
pub use appimage_file::AppImageFile;
pub use client_update::{ClientReleaseBundle, ClientReleaseStatus, PreparedClientRelease};
pub use installed_release::{
    InstallationDecision, InstallationDecisionKind, InstalledReleaseReceipt, InstalledReleaseStore,
    InstalledReleaseSummary, SYSTEM_RELEASE_STATE_DIRECTORY, SignedReleaseRecord,
    parse_receipt as parse_installed_release_receipt,
};
#[cfg(unix)]
pub use linux_debian_update::{DebianRecoveryAction, DebianRecoveryResult};
pub use trust::{
    BUNDLED_RELEASE_TRUST_ROOT_PEM, INSTALLED_RELEASE_TRUST_SCHEMA_VERSION, InstalledReleaseTrust,
    InstalledReleaseTrustSummary, LINUX_RELEASE_TRUST_STATE_NAME, MAX_TRUST_POLICY_BYTES,
    MAX_TRUST_SIGNATURE_BYTES, ReleaseTrustKey, ReleaseTrustPolicy, ReleaseTrustSignature,
    TrustPolicyAction, TrustPolicyDecision, VerifiedReleaseTrustPolicy, build_trust_policy,
    bundled_release_trust_root_id, encode_trust_policy, encode_trust_signature, parse_trust_policy,
    parse_trust_signature, sign_trust_policy, verify_manifest_with_trust_policy,
    verify_release_artifact_with_trust_policy, verify_release_directory_with_trust_policy,
    verify_trust_policy, verify_trust_policy_update,
};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use ed25519_dalek::{
    Signature, Signer, SigningKey, VerifyingKey,
    pkcs8::{
        DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey,
        spki::der::pem::LineEnding,
    },
};
use rand::{RngCore, rngs::OsRng};
use semver::Version;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    cmp::Ordering,
    collections::HashSet,
    fmt, fs,
    io::{self, Read},
    path::{Component, Path},
    str::FromStr,
};
use thiserror::Error;
use zeroize::Zeroizing;

pub const RELEASE_MANIFEST_SCHEMA_VERSION: u16 = 1;
pub const RELEASE_SIGNATURE_SCHEMA_VERSION: u16 = 1;
pub const COMPATIBILITY_CONTRACT_SCHEMA_VERSION: u16 = 1;
pub const INSTALLED_RELEASE_RECEIPT_SCHEMA_VERSION: u16 = 1;
pub const RELEASE_PRODUCT: &str = "sirinvpn";
pub const MAX_MANIFEST_BYTES: u64 = 256 * 1024;
pub const MAX_SIGNATURE_BYTES: u64 = 8 * 1024;
pub const MAX_KEY_BYTES: u64 = 16 * 1024;
pub const MAX_ARTIFACT_BYTES: u64 = 1024 * 1024 * 1024;

const SIGNATURE_DOMAIN: &[u8] = b"SirinVPN release manifest signature v1\0";
const MAX_ARTIFACTS: usize = 32;
const MAX_STATE_FORMATS: usize = 64;

#[derive(Debug, Error)]
pub enum ReleaseError {
    #[error("release file operation failed: {0}")]
    Io(#[from] io::Error),
    #[error("the release manifest is empty or exceeds 256 KiB")]
    ManifestSize,
    #[error("the release signature envelope is empty or exceeds 8 KiB")]
    SignatureSize,
    #[error("the release key is empty or exceeds 16 KiB")]
    KeySize,
    #[error("the release manifest is invalid")]
    InvalidManifest,
    #[error("the release manifest is not in canonical SirinVPN form")]
    NonCanonicalManifest,
    #[error("the release signature envelope is invalid")]
    InvalidSignatureEnvelope,
    #[error("the release signature envelope is not in canonical SirinVPN form")]
    NonCanonicalSignatureEnvelope,
    #[error("the release compatibility contract is invalid")]
    InvalidCompatibilityContract,
    #[error("the release compatibility contract is not in canonical SirinVPN form")]
    NonCanonicalCompatibilityContract,
    #[error("the installed release receipt is empty or exceeds 768 KiB")]
    InstalledReceiptSize,
    #[error("the installed release receipt is invalid")]
    InvalidInstalledReceipt,
    #[error("the installed release receipt is not in canonical SirinVPN form")]
    NonCanonicalInstalledReceipt,
    #[error("the installed release state is unsafe or has incorrect ownership or permissions")]
    UnsafeInstalledState,
    #[error(
        "first check the signed release matching the running application to bind its exact installed bytes"
    )]
    ClientBaselineRequired,
    #[error(
        "the installed application does not match its authenticated release; finish or recover its pending update"
    )]
    ClientInstalledMismatch,
    #[error("the release does not support this client update lifecycle")]
    ClientUpdateUnsupported,
    #[error(
        "an application update is pending; finish or explicitly cancel it before starting another"
    )]
    ClientUpdatePending,
    #[error("the application update recovery record is invalid; its files were preserved")]
    InvalidClientUpdateJournal,
    #[error("no compatible, currently trusted previous AppImage is available")]
    ClientRollbackUnavailable,
    #[error("the authenticated installed package cache is missing")]
    InstalledPackageCacheMissing,
    #[error("the authenticated installed package cache is invalid")]
    InvalidInstalledPackageCache,
    #[error("transactional Debian updates require an existing installed-release receipt")]
    DebianUpdateReceiptRequired,
    #[error("transactional Debian updates require same-target signed .deb artifacts")]
    DebianUpdateArtifactUnsupported,
    #[error("the current and candidate releases must support Linux release transaction schema 1")]
    DebianUpdateStateUnsupported,
    #[error("the Debian update journal is empty, oversized, invalid, or inconsistent")]
    InvalidDebianUpdateJournal,
    #[error("the Debian update journal is not in canonical SirinVPN form")]
    NonCanonicalDebianUpdateJournal,
    #[error("the VPN must be completely disconnected before a Debian package update")]
    DebianUpdateTunnelActive,
    #[error("the signed candidate is not a valid SirinVPN Debian package for this release target")]
    InvalidDebianPackage,
    #[error("the Debian package operation failed")]
    DebianPackageOperation,
    #[error("the installed SirinVPN Debian package failed its health check")]
    DebianPackageHealth,
    #[error("the Debian update failed and the previous authenticated package was restored")]
    DebianUpdateRolledBack,
    #[error(
        "the Debian update could not be recovered automatically; authenticated recovery state was retained"
    )]
    DebianUpdateRecoveryRequired,
    #[error(
        "signed VPS updates require an authenticated receipt for the currently installed server"
    )]
    ServerReceiptRequired,
    #[error("the installed VPS executable does not match its signed release")]
    ServerInstalledMismatch,
    #[error("the release does not support the VPS update transaction or handoff firewall guard")]
    ServerUpdateUnsupported,
    #[error("the VPS update recovery record is invalid or inconsistent")]
    InvalidServerUpdateJournal,
    #[error("the VPS update failed; the previous authenticated server was restored")]
    ServerUpdateRolledBack,
    #[error("the VPS update needs recovery; its authenticated recovery files were retained")]
    ServerUpdateRecoveryRequired,
    #[error("no previous authenticated VPS release is available for rollback")]
    ServerRollbackUnavailable,
    #[error("the VPS release operation failed: {0}")]
    ServerOperation(&'static str),
    #[error("the release signing key is invalid")]
    InvalidPrivateKey,
    #[error("the trusted release key is invalid")]
    InvalidPublicKey,
    #[error("the release signature key does not match the trusted key")]
    KeyIdMismatch,
    #[error("the release trust policy is empty or exceeds 128 KiB")]
    TrustPolicySize,
    #[error("the release trust signature envelope is empty or exceeds 8 KiB")]
    TrustSignatureSize,
    #[error("the release trust policy is invalid")]
    InvalidTrustPolicy,
    #[error("the release trust policy is not in canonical SirinVPN form")]
    NonCanonicalTrustPolicy,
    #[error("the release trust signature envelope is invalid")]
    InvalidTrustSignatureEnvelope,
    #[error("the release trust signature envelope is not in canonical SirinVPN form")]
    NonCanonicalTrustSignatureEnvelope,
    #[error("the release trust policy is signed by a different root")]
    TrustRootMismatch,
    #[error("the release trust policy digest does not match its signature envelope")]
    TrustPolicyDigestMismatch,
    #[error("the release trust policy signature is invalid")]
    InvalidTrustSignature,
    #[error("the release signing key is not active in the installed trust policy")]
    ReleaseKeyNotTrusted,
    #[error("the release signing key is revoked")]
    ReleaseKeyRevoked,
    #[error("installed trust state is required when no explicit legacy key is provided")]
    InstalledTrustRequired,
    #[error("the signed release does not support installed release trust schema 1")]
    InstalledTrustUnsupported,
    #[error("the existing release receipt cannot safely adopt installed trust state")]
    InstalledTrustAdoptionUnsupported,
    #[error("the first installed trust policy must authorize the receipt's pinned release key")]
    InstalledTrustDoesNotAuthorizeCurrentKey,
    #[error("an explicit legacy key cannot bypass installed release trust state")]
    InstalledTrustForbidsExplicitKey,
    #[error("release signing-key changes require a strict upgrade above the high watermark")]
    ReleaseKeyTransitionRequiresUpgrade,
    #[error("the installed release trust record is empty or exceeds its size limit")]
    InstalledTrustSize,
    #[error("the installed release trust record is invalid")]
    InvalidInstalledTrust,
    #[error("the installed release trust record is not in canonical SirinVPN form")]
    NonCanonicalInstalledTrust,
    #[error("the release trust policy sequence cannot move backward")]
    TrustPolicyRollback,
    #[error("a different release trust policy reuses the installed sequence")]
    TrustPolicySequenceCollision,
    #[error("a release trust policy cannot un-revoke a key")]
    TrustPolicyUnrevokesKey,
    #[error("a release trust policy must revoke every key it removes")]
    TrustPolicyRemovesKeyWithoutRevocation,
    #[error("the release manifest digest does not match its signature envelope")]
    ManifestDigestMismatch,
    #[error("the release manifest signature is invalid")]
    InvalidSignature,
    #[error("the release artifact is missing, unsafe, or unreadable: {0}")]
    InvalidArtifact(String),
    #[error("the release artifact exceeds 1 GiB: {0}")]
    ArtifactSize(String),
    #[error("the release artifact size does not match the signed manifest: {0}")]
    ArtifactSizeMismatch(String),
    #[error("the release artifact digest does not match the signed manifest: {0}")]
    ArtifactDigestMismatch(String),
    #[error("the signed release does not contain artifact {kind} for target {target}")]
    ArtifactUnavailable { kind: ArtifactKind, target: String },
    #[error("the release changes product or channel")]
    ReleaseTrackMismatch,
    #[error("the release version and sequence do not move in the same direction")]
    VersionSequenceMismatch,
    #[error("the selected release is not newer than the installed release")]
    NotNewer,
    #[error("selecting an older signed release requires explicit rollback confirmation")]
    RollbackConfirmationRequired,
    #[error("the selected release is below the highest accepted release sequence")]
    BelowHighestAcceptedRelease,
    #[error("a different signed manifest reuses an accepted release sequence")]
    ReleaseSequenceCollision,
    #[error("the selected release does not support installed release receipt schema 1")]
    InstalledReceiptUnsupported,
    #[error("installed release state accepts only a .deb, AppImage, or server executable")]
    InstalledArtifactUnsupported,
    #[error("the release changes the declared persistent-state set")]
    StateSetChanged,
    #[error("the candidate cannot read current state format {0}")]
    ForwardIncompatible(String),
    #[error("the current release cannot read candidate state format {0}; rollback would be unsafe")]
    RollbackIncompatible(String),
    #[error("release JSON encoding failed")]
    Encoding,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseChannel {
    Stable,
    Preview,
}

impl fmt::Display for ReleaseChannel {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Stable => "stable",
            Self::Preview => "preview",
        })
    }
}

impl FromStr for ReleaseChannel {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "stable" => Ok(Self::Stable),
            "preview" => Ok(Self::Preview),
            _ => Err("expected stable or preview".to_owned()),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactKind {
    #[serde(rename = "linux_appimage")]
    LinuxAppImage,
    LinuxDeb,
    AndroidApk,
    WindowsInstaller,
    ServerElf,
}

impl fmt::Display for ArtifactKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::LinuxAppImage => "linux_appimage",
            Self::LinuxDeb => "linux_deb",
            Self::AndroidApk => "android_apk",
            Self::WindowsInstaller => "windows_installer",
            Self::ServerElf => "server_elf",
        })
    }
}

impl FromStr for ArtifactKind {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "linux_appimage" => Ok(Self::LinuxAppImage),
            "linux_deb" => Ok(Self::LinuxDeb),
            "android_apk" => Ok(Self::AndroidApk),
            "windows_installer" => Ok(Self::WindowsInstaller),
            "server_elf" => Ok(Self::ServerElf),
            _ => Err(
                "expected linux_appimage, linux_deb, android_apk, windows_installer, or server_elf"
                    .to_owned(),
            ),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseArtifact {
    pub kind: ArtifactKind,
    pub target: String,
    pub file_name: String,
    pub size_bytes: u64,
    pub sha256: String,
}

impl ReleaseArtifact {
    pub fn from_path(
        kind: ArtifactKind,
        target: impl Into<String>,
        path: &Path,
    ) -> Result<Self, ReleaseError> {
        let file_name = path
            .file_name()
            .and_then(|value| value.to_str())
            .ok_or_else(|| ReleaseError::InvalidArtifact(path.display().to_string()))?
            .to_owned();
        let (size_bytes, sha256) = digest_artifact(path)?;
        let artifact = Self {
            kind,
            target: target.into(),
            file_name,
            size_bytes,
            sha256,
        };
        validate_artifact(&artifact)?;
        Ok(artifact)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SchemaRange {
    pub minimum: u16,
    pub maximum: u16,
}

impl SchemaRange {
    fn valid(self) -> bool {
        self.minimum > 0 && self.minimum <= self.maximum
    }

    fn contains(self, other: Self) -> bool {
        self.minimum <= other.minimum && self.maximum >= other.maximum
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StateCompatibility {
    pub state: String,
    pub reads: SchemaRange,
    pub writes: SchemaRange,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompatibilityContract {
    pub schema_version: u16,
    pub states: Vec<StateCompatibility>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseManifest {
    pub schema_version: u16,
    pub product: String,
    pub release_version: String,
    pub release_sequence: u64,
    pub channel: ReleaseChannel,
    pub security_update: bool,
    pub artifacts: Vec<ReleaseArtifact>,
    pub state_compatibility: Vec<StateCompatibility>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseSignature {
    pub schema_version: u16,
    pub key_id_sha256: String,
    pub manifest_sha256: String,
    pub signature: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct VerifiedManifest {
    pub manifest: ReleaseManifest,
    pub manifest_sha256: String,
    pub key_id_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct VerifiedRelease {
    pub manifest: ReleaseManifest,
    pub manifest_sha256: String,
    pub key_id_sha256: String,
    pub verified_artifacts: usize,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct VerifiedArtifactRelease {
    pub manifest: ReleaseManifest,
    pub manifest_sha256: String,
    pub key_id_sha256: String,
    pub artifact: ReleaseArtifact,
}

impl VerifiedRelease {
    pub fn artifact(
        &self,
        kind: ArtifactKind,
        target: &str,
    ) -> Result<&ReleaseArtifact, ReleaseError> {
        self.manifest
            .artifacts
            .iter()
            .find(|artifact| artifact.kind == kind && artifact.target == target)
            .ok_or_else(|| ReleaseError::ArtifactUnavailable {
                kind,
                target: target.to_owned(),
            })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UpdateDirection {
    Upgrade,
    Rollback,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct StateTransition {
    pub state: String,
    pub from_writes: SchemaRange,
    pub to_writes: SchemaRange,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct UpdatePlan {
    pub direction: UpdateDirection,
    pub security_update: bool,
    pub from_version: String,
    pub to_version: String,
    pub from_sequence: u64,
    pub to_sequence: u64,
    pub rollback_safe: bool,
    pub state_transitions: Vec<StateTransition>,
}

pub fn build_manifest(
    release_version: impl Into<String>,
    release_sequence: u64,
    channel: ReleaseChannel,
    security_update: bool,
    mut artifacts: Vec<ReleaseArtifact>,
    mut state_compatibility: Vec<StateCompatibility>,
) -> Result<ReleaseManifest, ReleaseError> {
    artifacts.sort_by(|left, right| {
        (&left.kind, &left.target, &left.file_name).cmp(&(
            &right.kind,
            &right.target,
            &right.file_name,
        ))
    });
    state_compatibility.sort_by(|left, right| left.state.cmp(&right.state));
    let manifest = ReleaseManifest {
        schema_version: RELEASE_MANIFEST_SCHEMA_VERSION,
        product: RELEASE_PRODUCT.to_owned(),
        release_version: release_version.into(),
        release_sequence,
        channel,
        security_update,
        artifacts,
        state_compatibility,
    };
    validate_manifest(&manifest)?;
    Ok(manifest)
}

pub fn encode_manifest(manifest: &ReleaseManifest) -> Result<Vec<u8>, ReleaseError> {
    validate_manifest(manifest)?;
    canonical_json(manifest)
}

pub fn parse_manifest(bytes: &[u8]) -> Result<ReleaseManifest, ReleaseError> {
    check_size(bytes, MAX_MANIFEST_BYTES, ReleaseError::ManifestSize)?;
    let manifest: ReleaseManifest =
        serde_json::from_slice(bytes).map_err(|_| ReleaseError::InvalidManifest)?;
    validate_manifest(&manifest)?;
    if canonical_json(&manifest)? != bytes {
        return Err(ReleaseError::NonCanonicalManifest);
    }
    Ok(manifest)
}

pub fn encode_compatibility_contract(
    contract: &CompatibilityContract,
) -> Result<Vec<u8>, ReleaseError> {
    validate_compatibility_contract(contract)?;
    canonical_json(contract)
}

pub fn parse_compatibility_contract(bytes: &[u8]) -> Result<CompatibilityContract, ReleaseError> {
    check_size(bytes, MAX_MANIFEST_BYTES, ReleaseError::ManifestSize)?;
    let contract: CompatibilityContract =
        serde_json::from_slice(bytes).map_err(|_| ReleaseError::InvalidCompatibilityContract)?;
    validate_compatibility_contract(&contract)?;
    if canonical_json(&contract)? != bytes {
        return Err(ReleaseError::NonCanonicalCompatibilityContract);
    }
    Ok(contract)
}

pub fn sign_manifest(
    manifest_bytes: &[u8],
    private_key_pem: &str,
) -> Result<Vec<u8>, ReleaseError> {
    let _ = parse_manifest(manifest_bytes)?;
    if private_key_pem.is_empty() || private_key_pem.len() as u64 > MAX_KEY_BYTES {
        return Err(ReleaseError::KeySize);
    }
    let signing_key =
        SigningKey::from_pkcs8_pem(private_key_pem).map_err(|_| ReleaseError::InvalidPrivateKey)?;
    let digest = Sha256::digest(manifest_bytes);
    let signature = signing_key.sign(&signature_message(&digest));
    let envelope = ReleaseSignature {
        schema_version: RELEASE_SIGNATURE_SCHEMA_VERSION,
        key_id_sha256: release_key_id(&signing_key.verifying_key()),
        manifest_sha256: hex::encode(digest),
        signature: STANDARD.encode(signature.to_bytes()),
    };
    canonical_json(&envelope)
}

pub fn encode_signature(envelope: &ReleaseSignature) -> Result<Vec<u8>, ReleaseError> {
    validate_signature_envelope(envelope)?;
    canonical_json(envelope)
}

pub fn parse_signature(bytes: &[u8]) -> Result<ReleaseSignature, ReleaseError> {
    check_size(bytes, MAX_SIGNATURE_BYTES, ReleaseError::SignatureSize)?;
    let envelope: ReleaseSignature =
        serde_json::from_slice(bytes).map_err(|_| ReleaseError::InvalidSignatureEnvelope)?;
    validate_signature_envelope(&envelope)?;
    if canonical_json(&envelope)? != bytes {
        return Err(ReleaseError::NonCanonicalSignatureEnvelope);
    }
    Ok(envelope)
}

pub fn verify_manifest(
    manifest_bytes: &[u8],
    signature_bytes: &[u8],
    public_key_pem: &str,
) -> Result<VerifiedManifest, ReleaseError> {
    let manifest = parse_manifest(manifest_bytes)?;
    if public_key_pem.is_empty() || public_key_pem.len() as u64 > MAX_KEY_BYTES {
        return Err(ReleaseError::KeySize);
    }
    let envelope = parse_signature(signature_bytes)?;
    let verifying_key = VerifyingKey::from_public_key_pem(public_key_pem)
        .map_err(|_| ReleaseError::InvalidPublicKey)?;
    let key_id = release_key_id(&verifying_key);
    if envelope.key_id_sha256 != key_id {
        return Err(ReleaseError::KeyIdMismatch);
    }
    let digest = Sha256::digest(manifest_bytes);
    let digest_hex = hex::encode(digest);
    if envelope.manifest_sha256 != digest_hex {
        return Err(ReleaseError::ManifestDigestMismatch);
    }
    let signature_bytes = STANDARD
        .decode(&envelope.signature)
        .map_err(|_| ReleaseError::InvalidSignatureEnvelope)?;
    if STANDARD.encode(&signature_bytes) != envelope.signature {
        return Err(ReleaseError::InvalidSignatureEnvelope);
    }
    let signature = Signature::from_slice(&signature_bytes)
        .map_err(|_| ReleaseError::InvalidSignatureEnvelope)?;
    verifying_key
        .verify_strict(&signature_message(&digest), &signature)
        .map_err(|_| ReleaseError::InvalidSignature)?;
    Ok(VerifiedManifest {
        manifest,
        manifest_sha256: digest_hex,
        key_id_sha256: key_id,
    })
}

pub fn verify_release_directory(
    manifest_bytes: &[u8],
    signature_bytes: &[u8],
    public_key_pem: &str,
    artifact_directory: &Path,
) -> Result<VerifiedRelease, ReleaseError> {
    let verified = verify_manifest(manifest_bytes, signature_bytes, public_key_pem)?;
    let metadata = fs::symlink_metadata(artifact_directory)?;
    if !metadata.file_type().is_dir() {
        return Err(ReleaseError::InvalidArtifact(
            artifact_directory.display().to_string(),
        ));
    }
    for artifact in &verified.manifest.artifacts {
        verify_artifact_bytes(artifact_directory, artifact)?;
    }
    Ok(VerifiedRelease {
        verified_artifacts: verified.manifest.artifacts.len(),
        manifest: verified.manifest,
        manifest_sha256: verified.manifest_sha256,
        key_id_sha256: verified.key_id_sha256,
    })
}

pub fn verify_release_artifact(
    manifest_bytes: &[u8],
    signature_bytes: &[u8],
    public_key_pem: &str,
    artifact_directory: &Path,
    kind: ArtifactKind,
    target: &str,
) -> Result<VerifiedArtifactRelease, ReleaseError> {
    let verified = verify_manifest(manifest_bytes, signature_bytes, public_key_pem)?;
    let directory_metadata = fs::symlink_metadata(artifact_directory)?;
    if !directory_metadata.file_type().is_dir() {
        return Err(ReleaseError::InvalidArtifact(
            artifact_directory.display().to_string(),
        ));
    }
    let artifact = verified
        .manifest
        .artifacts
        .iter()
        .find(|artifact| artifact.kind == kind && artifact.target == target)
        .cloned()
        .ok_or_else(|| ReleaseError::ArtifactUnavailable {
            kind,
            target: target.to_owned(),
        })?;
    verify_artifact_bytes(artifact_directory, &artifact)?;
    Ok(VerifiedArtifactRelease {
        manifest: verified.manifest,
        manifest_sha256: verified.manifest_sha256,
        key_id_sha256: verified.key_id_sha256,
        artifact,
    })
}

pub fn plan_transition(
    current: &ReleaseManifest,
    candidate: &ReleaseManifest,
    allow_rollback: bool,
) -> Result<UpdatePlan, ReleaseError> {
    validate_manifest(current)?;
    validate_manifest(candidate)?;
    if current.product != candidate.product || current.channel != candidate.channel {
        return Err(ReleaseError::ReleaseTrackMismatch);
    }
    let current_version = canonical_version(&current.release_version)?;
    let candidate_version = canonical_version(&candidate.release_version)?;
    let version_order = candidate_version.cmp(&current_version);
    let sequence_order = candidate.release_sequence.cmp(&current.release_sequence);
    let direction = match (version_order, sequence_order) {
        (Ordering::Greater, Ordering::Greater) => UpdateDirection::Upgrade,
        (Ordering::Less, Ordering::Less) if allow_rollback => UpdateDirection::Rollback,
        (Ordering::Less, Ordering::Less) => {
            return Err(ReleaseError::RollbackConfirmationRequired);
        }
        (Ordering::Equal, Ordering::Equal) => return Err(ReleaseError::NotNewer),
        _ => return Err(ReleaseError::VersionSequenceMismatch),
    };

    if current.state_compatibility.len() != candidate.state_compatibility.len()
        || current
            .state_compatibility
            .iter()
            .zip(&candidate.state_compatibility)
            .any(|(left, right)| left.state != right.state)
    {
        return Err(ReleaseError::StateSetChanged);
    }

    let mut state_transitions = Vec::new();
    for (from, to) in current
        .state_compatibility
        .iter()
        .zip(&candidate.state_compatibility)
    {
        if !to.reads.contains(from.writes) {
            return Err(ReleaseError::ForwardIncompatible(from.state.clone()));
        }
        if !from.reads.contains(to.writes) {
            return Err(ReleaseError::RollbackIncompatible(from.state.clone()));
        }
        if from.writes != to.writes {
            state_transitions.push(StateTransition {
                state: from.state.clone(),
                from_writes: from.writes,
                to_writes: to.writes,
            });
        }
    }

    Ok(UpdatePlan {
        direction,
        security_update: candidate.security_update,
        from_version: current.release_version.clone(),
        to_version: candidate.release_version.clone(),
        from_sequence: current.release_sequence,
        to_sequence: candidate.release_sequence,
        rollback_safe: true,
        state_transitions,
    })
}

pub fn generate_signing_keypair() -> Result<(Zeroizing<String>, String), ReleaseError> {
    let mut seed = Zeroizing::new([0_u8; 32]);
    OsRng.fill_bytes(seed.as_mut());
    let signing_key = SigningKey::from_bytes(&seed);
    let private_key = signing_key
        .to_pkcs8_pem(LineEnding::LF)
        .map_err(|_| ReleaseError::InvalidPrivateKey)?;
    let public_key = signing_key
        .verifying_key()
        .to_public_key_pem(LineEnding::LF)
        .map_err(|_| ReleaseError::InvalidPublicKey)?;
    Ok((private_key, public_key))
}

pub fn public_key_id(public_key_pem: &str) -> Result<String, ReleaseError> {
    if public_key_pem.is_empty() || public_key_pem.len() as u64 > MAX_KEY_BYTES {
        return Err(ReleaseError::KeySize);
    }
    let key = VerifyingKey::from_public_key_pem(public_key_pem)
        .map_err(|_| ReleaseError::InvalidPublicKey)?;
    Ok(release_key_id(&key))
}

pub(crate) fn canonical_public_key_pem(public_key_pem: &str) -> Result<String, ReleaseError> {
    if public_key_pem.is_empty() || public_key_pem.len() as u64 > MAX_KEY_BYTES {
        return Err(ReleaseError::KeySize);
    }
    VerifyingKey::from_public_key_pem(public_key_pem)
        .map_err(|_| ReleaseError::InvalidPublicKey)?
        .to_public_key_pem(LineEnding::LF)
        .map_err(|_| ReleaseError::InvalidPublicKey)
}

fn validate_manifest(manifest: &ReleaseManifest) -> Result<(), ReleaseError> {
    if manifest.schema_version != RELEASE_MANIFEST_SCHEMA_VERSION
        || manifest.product != RELEASE_PRODUCT
        || manifest.release_sequence == 0
        || manifest.release_version.len() > 64
        || manifest.artifacts.is_empty()
        || manifest.artifacts.len() > MAX_ARTIFACTS
        || manifest.state_compatibility.is_empty()
        || manifest.state_compatibility.len() > MAX_STATE_FORMATS
    {
        return Err(ReleaseError::InvalidManifest);
    }
    let version = canonical_version(&manifest.release_version)?;
    if manifest.channel == ReleaseChannel::Stable && !version.pre.is_empty() {
        return Err(ReleaseError::InvalidManifest);
    }

    let mut artifact_slots = HashSet::new();
    let mut artifact_names = HashSet::new();
    for artifact in &manifest.artifacts {
        validate_artifact(artifact)?;
        if !artifact_slots.insert((artifact.kind, artifact.target.as_str()))
            || !artifact_names.insert(artifact.file_name.as_str())
        {
            return Err(ReleaseError::InvalidManifest);
        }
    }
    if !manifest.artifacts.windows(2).all(|items| {
        (&items[0].kind, &items[0].target, &items[0].file_name)
            < (&items[1].kind, &items[1].target, &items[1].file_name)
    }) {
        return Err(ReleaseError::InvalidManifest);
    }
    validate_states(&manifest.state_compatibility).map_err(|_| ReleaseError::InvalidManifest)
}

fn validate_compatibility_contract(contract: &CompatibilityContract) -> Result<(), ReleaseError> {
    if contract.schema_version != COMPATIBILITY_CONTRACT_SCHEMA_VERSION
        || contract.states.is_empty()
        || contract.states.len() > MAX_STATE_FORMATS
    {
        return Err(ReleaseError::InvalidCompatibilityContract);
    }
    validate_states(&contract.states).map_err(|_| ReleaseError::InvalidCompatibilityContract)
}

fn validate_states(states: &[StateCompatibility]) -> Result<(), ()> {
    let mut names = HashSet::new();
    for state in states {
        if !valid_identifier(&state.state, 64)
            || !state.reads.valid()
            || !state.writes.valid()
            || !names.insert(state.state.as_str())
        {
            return Err(());
        }
    }
    if !states
        .windows(2)
        .all(|items| items[0].state < items[1].state)
    {
        return Err(());
    }
    Ok(())
}

pub(crate) fn validate_artifact(artifact: &ReleaseArtifact) -> Result<(), ReleaseError> {
    if !valid_target(&artifact.target)
        || !valid_file_name(&artifact.file_name)
        || artifact.size_bytes == 0
        || artifact.size_bytes > MAX_ARTIFACT_BYTES
        || !valid_sha256(&artifact.sha256)
    {
        return Err(ReleaseError::InvalidArtifact(artifact.file_name.clone()));
    }
    Ok(())
}

fn validate_signature_envelope(envelope: &ReleaseSignature) -> Result<(), ReleaseError> {
    if envelope.schema_version != RELEASE_SIGNATURE_SCHEMA_VERSION
        || !valid_sha256(&envelope.key_id_sha256)
        || !valid_sha256(&envelope.manifest_sha256)
        || envelope.signature.is_empty()
        || envelope.signature.len() > 128
    {
        return Err(ReleaseError::InvalidSignatureEnvelope);
    }
    Ok(())
}

fn canonical_version(value: &str) -> Result<Version, ReleaseError> {
    let version = Version::parse(value).map_err(|_| ReleaseError::InvalidManifest)?;
    if version.to_string() != value {
        return Err(ReleaseError::InvalidManifest);
    }
    Ok(version)
}

fn valid_target(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 96
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}

fn valid_file_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 255
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b'+'))
        && Path::new(value).components().count() == 1
        && matches!(
            Path::new(value).components().next(),
            Some(Component::Normal(_))
        )
}

fn valid_identifier(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || (index > 0 && byte == b'_')
        })
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn canonical_json(value: &impl Serialize) -> Result<Vec<u8>, ReleaseError> {
    let mut bytes = serde_json::to_vec_pretty(value).map_err(|_| ReleaseError::Encoding)?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn check_size(bytes: &[u8], maximum: u64, error: ReleaseError) -> Result<(), ReleaseError> {
    if bytes.is_empty() || bytes.len() as u64 > maximum {
        return Err(error);
    }
    Ok(())
}

fn signature_message(digest: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(SIGNATURE_DOMAIN.len() + digest.len());
    message.extend_from_slice(SIGNATURE_DOMAIN);
    message.extend_from_slice(digest);
    message
}

fn release_key_id(key: &VerifyingKey) -> String {
    hex::encode(Sha256::digest(key.as_bytes()))
}

fn digest_artifact(path: &Path) -> Result<(u64, String), ReleaseError> {
    let file = sirinvpn_platform::files::open_no_follow(path)
        .map_err(|_| ReleaseError::InvalidArtifact(path.display().to_string()))?;
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file() {
        return Err(ReleaseError::InvalidArtifact(path.display().to_string()));
    }
    if metadata.len() == 0 {
        return Err(ReleaseError::InvalidArtifact(path.display().to_string()));
    }
    if metadata.len() > MAX_ARTIFACT_BYTES {
        return Err(ReleaseError::ArtifactSize(path.display().to_string()));
    }
    let mut reader = file.take(MAX_ARTIFACT_BYTES + 1);
    let mut digest = Sha256::new();
    let size = io::copy(&mut reader, &mut digest)?;
    if size > MAX_ARTIFACT_BYTES {
        return Err(ReleaseError::ArtifactSize(path.display().to_string()));
    }
    if size == 0 {
        return Err(ReleaseError::InvalidArtifact(path.display().to_string()));
    }
    Ok((size, hex::encode(digest.finalize())))
}

fn verify_artifact_bytes(
    artifact_directory: &Path,
    artifact: &ReleaseArtifact,
) -> Result<(), ReleaseError> {
    let path = artifact_directory.join(&artifact.file_name);
    let (size, digest) = digest_artifact(&path)?;
    if size != artifact.size_bytes {
        return Err(ReleaseError::ArtifactSizeMismatch(
            artifact.file_name.clone(),
        ));
    }
    if digest != artifact.sha256 {
        return Err(ReleaseError::ArtifactDigestMismatch(
            artifact.file_name.clone(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
