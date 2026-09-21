use crate::{
    ReleaseError, VerifiedArtifactRelease, VerifiedManifest, VerifiedRelease, canonical_json,
    canonical_public_key_pem, parse_signature, public_key_id, verify_manifest,
    verify_release_artifact, verify_release_directory,
};
mod verification;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use ed25519_dalek::{
    Signature, Signer, SigningKey, VerifyingKey,
    pkcs8::{DecodePrivateKey, DecodePublicKey},
};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::HashSet, fs, io::Read, path::Path};
pub use verification::verify_trust_policy_update;

pub const RELEASE_TRUST_POLICY_SCHEMA_VERSION: u16 = 1;
pub const RELEASE_TRUST_SIGNATURE_SCHEMA_VERSION: u16 = 1;
pub const INSTALLED_RELEASE_TRUST_SCHEMA_VERSION: u16 = 1;
pub const LINUX_RELEASE_TRUST_STATE_NAME: &str = "linux_release_trust";
pub const MAX_TRUST_POLICY_BYTES: u64 = 128 * 1024;
pub const MAX_TRUST_SIGNATURE_BYTES: u64 = 8 * 1024;
pub const BUNDLED_RELEASE_TRUST_ROOT_PEM: &str =
    include_str!("../../../release/release-trust-root.pub");

const TRUST_FILE_NAME: &str = "trust.json";
const TRUST_SIGNATURE_DOMAIN: &[u8] = b"SirinVPN release trust policy signature v1\0";
const MAX_ACTIVE_RELEASE_KEYS: usize = 16;
const MAX_REVOKED_RELEASE_KEYS: usize = 128;
const MAX_INSTALLED_TRUST_BYTES: u64 = MAX_TRUST_POLICY_BYTES + MAX_TRUST_SIGNATURE_BYTES + 1024;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseTrustKey {
    pub key_id_sha256: String,
    pub public_key_pem: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseTrustPolicy {
    pub schema_version: u16,
    pub product: String,
    pub sequence: u64,
    pub active_release_keys: Vec<ReleaseTrustKey>,
    pub revoked_release_key_ids: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseTrustSignature {
    pub schema_version: u16,
    pub root_key_id_sha256: String,
    pub policy_sha256: String,
    pub signature: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct VerifiedReleaseTrustPolicy {
    pub policy: ReleaseTrustPolicy,
    pub policy_sha256: String,
    pub root_key_id_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstalledReleaseTrust {
    pub schema_version: u16,
    pub policy: ReleaseTrustPolicy,
    pub signature: ReleaseTrustSignature,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustPolicyAction {
    Initialize,
    Update,
    AlreadyCurrent,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct InstalledReleaseTrustSummary {
    pub schema_version: u16,
    pub policy_sequence: u64,
    pub policy_sha256: String,
    pub root_key_id_sha256: String,
    pub active_release_key_ids: Vec<String>,
    pub revoked_release_key_ids: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct TrustPolicyDecision {
    pub action: TrustPolicyAction,
    pub state: InstalledReleaseTrustSummary,
}

pub fn bundled_release_trust_root_id() -> Result<String, ReleaseError> {
    public_key_id(BUNDLED_RELEASE_TRUST_ROOT_PEM)
}

pub fn build_trust_policy(
    sequence: u64,
    release_public_keys: Vec<String>,
    mut revoked_release_key_ids: Vec<String>,
) -> Result<ReleaseTrustPolicy, ReleaseError> {
    let mut active_release_keys = release_public_keys
        .into_iter()
        .map(|public_key_pem| {
            let public_key_pem = canonical_public_key_pem(&public_key_pem)?;
            Ok(ReleaseTrustKey {
                key_id_sha256: public_key_id(&public_key_pem)?,
                public_key_pem,
            })
        })
        .collect::<Result<Vec<_>, ReleaseError>>()?;
    active_release_keys.sort_by(|left, right| left.key_id_sha256.cmp(&right.key_id_sha256));
    revoked_release_key_ids.sort();
    let policy = ReleaseTrustPolicy {
        schema_version: RELEASE_TRUST_POLICY_SCHEMA_VERSION,
        product: crate::RELEASE_PRODUCT.to_owned(),
        sequence,
        active_release_keys,
        revoked_release_key_ids,
    };
    validate_trust_policy(&policy)?;
    Ok(policy)
}

pub fn encode_trust_policy(policy: &ReleaseTrustPolicy) -> Result<Vec<u8>, ReleaseError> {
    validate_trust_policy(policy)?;
    canonical_json(policy)
}

pub fn parse_trust_policy(bytes: &[u8]) -> Result<ReleaseTrustPolicy, ReleaseError> {
    check_size(bytes, MAX_TRUST_POLICY_BYTES, ReleaseError::TrustPolicySize)?;
    let policy: ReleaseTrustPolicy =
        serde_json::from_slice(bytes).map_err(|_| ReleaseError::InvalidTrustPolicy)?;
    validate_trust_policy(&policy)?;
    if canonical_json(&policy)? != bytes {
        return Err(ReleaseError::NonCanonicalTrustPolicy);
    }
    Ok(policy)
}

pub fn sign_trust_policy(
    policy_bytes: &[u8],
    root_private_key_pem: &str,
) -> Result<Vec<u8>, ReleaseError> {
    let _ = parse_trust_policy(policy_bytes)?;
    if root_private_key_pem.is_empty() || root_private_key_pem.len() as u64 > crate::MAX_KEY_BYTES {
        return Err(ReleaseError::KeySize);
    }
    let signing_key = SigningKey::from_pkcs8_pem(root_private_key_pem)
        .map_err(|_| ReleaseError::InvalidPrivateKey)?;
    let digest = Sha256::digest(policy_bytes);
    let signature = signing_key.sign(&trust_signature_message(&digest));
    let envelope = ReleaseTrustSignature {
        schema_version: RELEASE_TRUST_SIGNATURE_SCHEMA_VERSION,
        root_key_id_sha256: key_id(&signing_key.verifying_key()),
        policy_sha256: hex::encode(digest),
        signature: STANDARD.encode(signature.to_bytes()),
    };
    encode_trust_signature(&envelope)
}

pub fn encode_trust_signature(envelope: &ReleaseTrustSignature) -> Result<Vec<u8>, ReleaseError> {
    validate_trust_signature(envelope)?;
    canonical_json(envelope)
}

pub fn parse_trust_signature(bytes: &[u8]) -> Result<ReleaseTrustSignature, ReleaseError> {
    check_size(
        bytes,
        MAX_TRUST_SIGNATURE_BYTES,
        ReleaseError::TrustSignatureSize,
    )?;
    let envelope: ReleaseTrustSignature =
        serde_json::from_slice(bytes).map_err(|_| ReleaseError::InvalidTrustSignatureEnvelope)?;
    validate_trust_signature(&envelope)?;
    if canonical_json(&envelope)? != bytes {
        return Err(ReleaseError::NonCanonicalTrustSignatureEnvelope);
    }
    Ok(envelope)
}

pub fn verify_trust_policy(
    policy_bytes: &[u8],
    signature_bytes: &[u8],
    root_public_key_pem: &str,
) -> Result<VerifiedReleaseTrustPolicy, ReleaseError> {
    let policy = parse_trust_policy(policy_bytes)?;
    let envelope = parse_trust_signature(signature_bytes)?;
    let canonical_root = canonical_public_key_pem(root_public_key_pem)?;
    let root_key = VerifyingKey::from_public_key_pem(&canonical_root)
        .map_err(|_| ReleaseError::InvalidPublicKey)?;
    let root_key_id = key_id(&root_key);
    if envelope.root_key_id_sha256 != root_key_id {
        return Err(ReleaseError::TrustRootMismatch);
    }
    if policy
        .active_release_keys
        .iter()
        .any(|key| key.key_id_sha256 == root_key_id)
        || policy
            .revoked_release_key_ids
            .iter()
            .any(|key_id| key_id == &root_key_id)
    {
        return Err(ReleaseError::InvalidTrustPolicy);
    }
    let digest = Sha256::digest(policy_bytes);
    let digest_hex = hex::encode(digest);
    if envelope.policy_sha256 != digest_hex {
        return Err(ReleaseError::TrustPolicyDigestMismatch);
    }
    let signature_bytes = STANDARD
        .decode(&envelope.signature)
        .map_err(|_| ReleaseError::InvalidTrustSignatureEnvelope)?;
    if STANDARD.encode(&signature_bytes) != envelope.signature {
        return Err(ReleaseError::InvalidTrustSignatureEnvelope);
    }
    let signature = Signature::from_slice(&signature_bytes)
        .map_err(|_| ReleaseError::InvalidTrustSignatureEnvelope)?;
    root_key
        .verify_strict(&trust_signature_message(&digest), &signature)
        .map_err(|_| ReleaseError::InvalidTrustSignature)?;
    Ok(VerifiedReleaseTrustPolicy {
        policy,
        policy_sha256: digest_hex,
        root_key_id_sha256: root_key_id,
    })
}

pub fn verify_manifest_with_trust_policy(
    manifest_bytes: &[u8],
    signature_bytes: &[u8],
    trust: &VerifiedReleaseTrustPolicy,
) -> Result<VerifiedManifest, ReleaseError> {
    let public_key = trusted_release_public_key(signature_bytes, trust)?;
    verify_manifest(manifest_bytes, signature_bytes, public_key)
}

pub fn verify_release_directory_with_trust_policy(
    manifest_bytes: &[u8],
    signature_bytes: &[u8],
    trust: &VerifiedReleaseTrustPolicy,
    artifact_directory: &Path,
) -> Result<VerifiedRelease, ReleaseError> {
    let public_key = trusted_release_public_key(signature_bytes, trust)?;
    verify_release_directory(
        manifest_bytes,
        signature_bytes,
        public_key,
        artifact_directory,
    )
}

pub fn verify_release_artifact_with_trust_policy(
    manifest_bytes: &[u8],
    signature_bytes: &[u8],
    trust: &VerifiedReleaseTrustPolicy,
    artifact_directory: &Path,
    kind: crate::ArtifactKind,
    target: &str,
) -> Result<VerifiedArtifactRelease, ReleaseError> {
    let public_key = trusted_release_public_key(signature_bytes, trust)?;
    verify_release_artifact(
        manifest_bytes,
        signature_bytes,
        public_key,
        artifact_directory,
        kind,
        target,
    )
}

fn trusted_release_public_key<'a>(
    signature_bytes: &[u8],
    trust: &'a VerifiedReleaseTrustPolicy,
) -> Result<&'a str, ReleaseError> {
    let signature = parse_signature(signature_bytes)?;
    if trust
        .policy
        .revoked_release_key_ids
        .iter()
        .any(|key_id| key_id == &signature.key_id_sha256)
    {
        return Err(ReleaseError::ReleaseKeyRevoked);
    }
    trust
        .policy
        .active_release_keys
        .iter()
        .find(|key| key.key_id_sha256 == signature.key_id_sha256)
        .map(|key| key.public_key_pem.as_str())
        .ok_or(ReleaseError::ReleaseKeyNotTrusted)
}

impl crate::InstalledReleaseStore {
    pub fn apply_trust_policy(
        &self,
        policy_bytes: &[u8],
        signature_bytes: &[u8],
    ) -> Result<TrustPolicyDecision, ReleaseError> {
        self.apply_trust_policy_with_root(
            policy_bytes,
            signature_bytes,
            BUNDLED_RELEASE_TRUST_ROOT_PEM,
        )
    }

    pub fn inspect_trust(&self) -> Result<Option<InstalledReleaseTrustSummary>, ReleaseError> {
        if !self.validate_existing_directory()? {
            return Ok(None);
        }
        let lock = self.open_lock()?;
        FileExt::lock_shared(&lock)?;
        let result = self
            .read_trust_unlocked()
            .map(|trust| trust.map(|value| summarize_trust(&value)));
        crate::installed_release::finish_locked(lock, result)
    }

    pub(crate) fn apply_trust_policy_with_root(
        &self,
        policy_bytes: &[u8],
        signature_bytes: &[u8],
        root_public_key_pem: &str,
    ) -> Result<TrustPolicyDecision, ReleaseError> {
        let verified = verify_trust_policy(policy_bytes, signature_bytes, root_public_key_pem)?;
        let candidate = InstalledReleaseTrust {
            schema_version: INSTALLED_RELEASE_TRUST_SCHEMA_VERSION,
            policy: verified.policy,
            signature: parse_trust_signature(signature_bytes)?,
        };
        self.ensure_directory()?;
        let lock = self.open_lock()?;
        FileExt::lock_exclusive(&lock)?;
        let result = (|| {
            let current = self.read_trust_unlocked_with_root(root_public_key_pem)?;
            if current.is_none()
                && let Some(receipt) = self.read_receipt_unlocked()?
            {
                crate::installed_release::require_trust_schema_support(
                    &receipt.active_release.manifest,
                )
                .and_then(|()| {
                    crate::installed_release::require_trust_schema_support(
                        &receipt.highest_accepted_release.manifest,
                    )
                })
                .map_err(|_| ReleaseError::InstalledTrustAdoptionUnsupported)?;
                let pinned_key_id = public_key_id(&receipt.trusted_public_key_pem)
                    .map_err(|_| ReleaseError::InvalidInstalledReceipt)?;
                if !candidate
                    .policy
                    .active_release_keys
                    .iter()
                    .any(|key| key.key_id_sha256 == pinned_key_id)
                {
                    return Err(ReleaseError::InstalledTrustDoesNotAuthorizeCurrentKey);
                }
            }
            let action = evaluate_trust_update(current.as_ref(), &candidate)?;
            if action != TrustPolicyAction::AlreadyCurrent {
                self.write_trust_unlocked_with_root(&candidate, root_public_key_pem)?;
            }
            Ok(TrustPolicyDecision {
                action,
                state: summarize_trust_with_root(&candidate, root_public_key_pem)?,
            })
        })();
        crate::installed_release::finish_locked(lock, result)
    }

    pub(crate) fn trust_path(&self) -> std::path::PathBuf {
        self.state_directory().join(TRUST_FILE_NAME)
    }

    pub(crate) fn trust_entry_exists_unlocked(&self) -> Result<bool, ReleaseError> {
        match fs::symlink_metadata(self.trust_path()) {
            Ok(_) => Ok(true),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(error.into()),
        }
    }

    pub(crate) fn read_trust_unlocked(
        &self,
    ) -> Result<Option<InstalledReleaseTrust>, ReleaseError> {
        self.read_trust_unlocked_with_root(BUNDLED_RELEASE_TRUST_ROOT_PEM)
    }

    pub(crate) fn read_trust_unlocked_with_root(
        &self,
        root_public_key_pem: &str,
    ) -> Result<Option<InstalledReleaseTrust>, ReleaseError> {
        let path = self.trust_path();
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        crate::installed_release::validate_private_file_metadata(&metadata)?;
        if metadata.len() == 0 || metadata.len() > MAX_INSTALLED_TRUST_BYTES {
            return Err(ReleaseError::InstalledTrustSize);
        }
        let file = sirinvpn_platform::files::open_no_follow(&path)?;
        self.validate_state_file(&file)?;
        crate::installed_release::validate_private_file_metadata(&file.metadata()?)?;
        let mut bytes = Vec::with_capacity(metadata.len() as usize);
        file.take(MAX_INSTALLED_TRUST_BYTES + 1)
            .read_to_end(&mut bytes)?;
        let trust: InstalledReleaseTrust =
            serde_json::from_slice(&bytes).map_err(|_| ReleaseError::InvalidInstalledTrust)?;
        validate_installed_trust(&trust, root_public_key_pem)?;
        if canonical_json(&trust)? != bytes {
            return Err(ReleaseError::NonCanonicalInstalledTrust);
        }
        Ok(Some(trust))
    }

    fn write_trust_unlocked_with_root(
        &self,
        trust: &InstalledReleaseTrust,
        root_public_key_pem: &str,
    ) -> Result<(), ReleaseError> {
        validate_installed_trust(trust, root_public_key_pem)?;
        let bytes = canonical_json(trust)?;
        if bytes.len() as u64 > MAX_INSTALLED_TRUST_BYTES {
            return Err(ReleaseError::InstalledTrustSize);
        }
        self.write_state(&self.trust_path(), &bytes)?;
        Ok(())
    }
}

pub(crate) fn verify_installed_trust(
    trust: &InstalledReleaseTrust,
    root_public_key_pem: &str,
) -> Result<VerifiedReleaseTrustPolicy, ReleaseError> {
    validate_installed_trust(trust, root_public_key_pem)?;
    let policy = encode_trust_policy(&trust.policy)?;
    let signature = encode_trust_signature(&trust.signature)?;
    verify_trust_policy(&policy, &signature, root_public_key_pem)
}

fn validate_installed_trust(
    trust: &InstalledReleaseTrust,
    root_public_key_pem: &str,
) -> Result<(), ReleaseError> {
    if trust.schema_version != INSTALLED_RELEASE_TRUST_SCHEMA_VERSION {
        return Err(ReleaseError::InvalidInstalledTrust);
    }
    let policy =
        encode_trust_policy(&trust.policy).map_err(|_| ReleaseError::InvalidInstalledTrust)?;
    let signature = encode_trust_signature(&trust.signature)
        .map_err(|_| ReleaseError::InvalidInstalledTrust)?;
    verify_trust_policy(&policy, &signature, root_public_key_pem)
        .map_err(|_| ReleaseError::InvalidInstalledTrust)?;
    Ok(())
}

fn evaluate_trust_update(
    current: Option<&InstalledReleaseTrust>,
    candidate: &InstalledReleaseTrust,
) -> Result<TrustPolicyAction, ReleaseError> {
    let Some(current) = current else {
        return Ok(TrustPolicyAction::Initialize);
    };
    match candidate.policy.sequence.cmp(&current.policy.sequence) {
        std::cmp::Ordering::Less => return Err(ReleaseError::TrustPolicyRollback),
        std::cmp::Ordering::Equal => {
            return if candidate == current {
                Ok(TrustPolicyAction::AlreadyCurrent)
            } else {
                Err(ReleaseError::TrustPolicySequenceCollision)
            };
        }
        std::cmp::Ordering::Greater => {}
    }

    let candidate_revoked = candidate
        .policy
        .revoked_release_key_ids
        .iter()
        .map(String::as_str)
        .collect::<HashSet<_>>();
    if current
        .policy
        .revoked_release_key_ids
        .iter()
        .any(|key_id| !candidate_revoked.contains(key_id.as_str()))
    {
        return Err(ReleaseError::TrustPolicyUnrevokesKey);
    }
    let candidate_active = candidate
        .policy
        .active_release_keys
        .iter()
        .map(|key| key.key_id_sha256.as_str())
        .collect::<HashSet<_>>();
    if current.policy.active_release_keys.iter().any(|key| {
        !candidate_active.contains(key.key_id_sha256.as_str())
            && !candidate_revoked.contains(key.key_id_sha256.as_str())
    }) {
        return Err(ReleaseError::TrustPolicyRemovesKeyWithoutRevocation);
    }
    Ok(TrustPolicyAction::Update)
}

fn summarize_trust(trust: &InstalledReleaseTrust) -> InstalledReleaseTrustSummary {
    summarize_trust_with_root(trust, BUNDLED_RELEASE_TRUST_ROOT_PEM)
        .expect("validated installed trust uses the bundled root")
}

fn summarize_trust_with_root(
    trust: &InstalledReleaseTrust,
    root_public_key_pem: &str,
) -> Result<InstalledReleaseTrustSummary, ReleaseError> {
    let verified = verify_installed_trust(trust, root_public_key_pem)?;
    Ok(InstalledReleaseTrustSummary {
        schema_version: trust.schema_version,
        policy_sequence: trust.policy.sequence,
        policy_sha256: verified.policy_sha256,
        root_key_id_sha256: verified.root_key_id_sha256,
        active_release_key_ids: trust
            .policy
            .active_release_keys
            .iter()
            .map(|key| key.key_id_sha256.clone())
            .collect(),
        revoked_release_key_ids: trust.policy.revoked_release_key_ids.clone(),
    })
}

fn validate_trust_policy(policy: &ReleaseTrustPolicy) -> Result<(), ReleaseError> {
    if policy.schema_version != RELEASE_TRUST_POLICY_SCHEMA_VERSION
        || policy.product != crate::RELEASE_PRODUCT
        || policy.sequence == 0
        || policy.active_release_keys.is_empty()
        || policy.active_release_keys.len() > MAX_ACTIVE_RELEASE_KEYS
        || policy.revoked_release_key_ids.len() > MAX_REVOKED_RELEASE_KEYS
    {
        return Err(ReleaseError::InvalidTrustPolicy);
    }
    let mut prior_key_id: Option<&str> = None;
    for key in &policy.active_release_keys {
        if !valid_sha256(&key.key_id_sha256)
            || prior_key_id.is_some_and(|prior| prior >= key.key_id_sha256.as_str())
        {
            return Err(ReleaseError::InvalidTrustPolicy);
        }
        let canonical = canonical_public_key_pem(&key.public_key_pem)
            .map_err(|_| ReleaseError::InvalidTrustPolicy)?;
        if canonical != key.public_key_pem
            || public_key_id(&canonical).map_err(|_| ReleaseError::InvalidTrustPolicy)?
                != key.key_id_sha256
        {
            return Err(ReleaseError::InvalidTrustPolicy);
        }
        prior_key_id = Some(&key.key_id_sha256);
    }
    let active = policy
        .active_release_keys
        .iter()
        .map(|key| key.key_id_sha256.as_str())
        .collect::<HashSet<_>>();
    let mut prior_revoked: Option<&str> = None;
    for key_id in &policy.revoked_release_key_ids {
        if !valid_sha256(key_id)
            || active.contains(key_id.as_str())
            || prior_revoked.is_some_and(|prior| prior >= key_id.as_str())
        {
            return Err(ReleaseError::InvalidTrustPolicy);
        }
        prior_revoked = Some(key_id);
    }
    Ok(())
}

fn validate_trust_signature(envelope: &ReleaseTrustSignature) -> Result<(), ReleaseError> {
    if envelope.schema_version != RELEASE_TRUST_SIGNATURE_SCHEMA_VERSION
        || !valid_sha256(&envelope.root_key_id_sha256)
        || !valid_sha256(&envelope.policy_sha256)
        || envelope.signature.len() > 128
    {
        return Err(ReleaseError::InvalidTrustSignatureEnvelope);
    }
    let bytes = STANDARD
        .decode(&envelope.signature)
        .map_err(|_| ReleaseError::InvalidTrustSignatureEnvelope)?;
    if bytes.len() != 64 || STANDARD.encode(bytes) != envelope.signature {
        return Err(ReleaseError::InvalidTrustSignatureEnvelope);
    }
    Ok(())
}

fn trust_signature_message(digest: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(TRUST_SIGNATURE_DOMAIN.len() + digest.len());
    message.extend_from_slice(TRUST_SIGNATURE_DOMAIN);
    message.extend_from_slice(digest);
    message
}

fn key_id(key: &VerifyingKey) -> String {
    hex::encode(Sha256::digest(key.as_bytes()))
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn check_size(bytes: &[u8], maximum: u64, error: ReleaseError) -> Result<(), ReleaseError> {
    if bytes.is_empty() || bytes.len() as u64 > maximum {
        Err(error)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::generate_signing_keypair;
    use std::os::unix::fs::{PermissionsExt, symlink};

    struct KeyPair {
        private: zeroize::Zeroizing<String>,
        public: String,
    }

    fn keys() -> KeyPair {
        let (private, public) = generate_signing_keypair().unwrap();
        KeyPair { private, public }
    }

    fn signed_policy(
        root: &KeyPair,
        sequence: u64,
        active: &[&KeyPair],
        revoked: Vec<String>,
    ) -> (Vec<u8>, Vec<u8>) {
        let policy = build_trust_policy(
            sequence,
            active.iter().map(|key| key.public.clone()).collect(),
            revoked,
        )
        .unwrap();
        let policy = encode_trust_policy(&policy).unwrap();
        let signature = sign_trust_policy(&policy, &root.private).unwrap();
        (policy, signature)
    }

    #[test]
    fn bundled_root_is_canonical_and_has_the_recorded_identity() {
        assert_eq!(
            canonical_public_key_pem(BUNDLED_RELEASE_TRUST_ROOT_PEM).unwrap(),
            BUNDLED_RELEASE_TRUST_ROOT_PEM
        );
        assert_eq!(
            bundled_release_trust_root_id().unwrap(),
            "0ff86fa15621859d9145a63b4d3690fd7de3ec4946f8ca7d0645b870ceec954b"
        );
    }

    #[test]
    fn trust_policy_signature_is_domain_separated_and_strict() {
        let root = keys();
        let release = keys();
        let (policy, signature) = signed_policy(&root, 1, &[&release], vec![]);
        let verified = verify_trust_policy(&policy, &signature, &root.public).unwrap();
        assert_eq!(verified.policy.sequence, 1);
        assert_eq!(verified.policy.active_release_keys.len(), 1);

        let wrong_root = keys();
        assert!(matches!(
            verify_trust_policy(&policy, &signature, &wrong_root.public),
            Err(ReleaseError::TrustRootMismatch)
        ));
        let mut changed = parse_trust_policy(&policy).unwrap();
        changed.sequence = 2;
        let changed = encode_trust_policy(&changed).unwrap();
        assert!(matches!(
            verify_trust_policy(&changed, &signature, &root.public),
            Err(ReleaseError::TrustPolicyDigestMismatch)
        ));
        let compact = serde_json::to_vec(&parse_trust_policy(&policy).unwrap()).unwrap();
        assert!(matches!(
            parse_trust_policy(&compact),
            Err(ReleaseError::NonCanonicalTrustPolicy)
        ));
    }

    #[test]
    fn policy_rejects_duplicate_active_revoked_and_root_keys() {
        let root = keys();
        let release = keys();
        assert!(matches!(
            build_trust_policy(
                1,
                vec![release.public.clone(), release.public.clone()],
                vec![]
            ),
            Err(ReleaseError::InvalidTrustPolicy)
        ));
        let release_id = public_key_id(&release.public).unwrap();
        assert!(matches!(
            build_trust_policy(1, vec![release.public], vec![release_id]),
            Err(ReleaseError::InvalidTrustPolicy)
        ));
        let (policy, signature) = signed_policy(&root, 1, &[&root], vec![]);
        assert!(matches!(
            verify_trust_policy(&policy, &signature, &root.public),
            Err(ReleaseError::InvalidTrustPolicy)
        ));
    }

    #[test]
    fn installed_policy_rotation_and_revocation_are_monotonic_and_idempotent() {
        let directory = tempfile::tempdir().unwrap();
        let store = crate::InstalledReleaseStore::new(directory.path().join("state"));
        let root = keys();
        let old = keys();
        let new = keys();
        let old_id = public_key_id(&old.public).unwrap();
        let (first_policy, first_signature) = signed_policy(&root, 1, &[&old], vec![]);
        let initialized = store
            .apply_trust_policy_with_root(&first_policy, &first_signature, &root.public)
            .unwrap();
        assert_eq!(initialized.action, TrustPolicyAction::Initialize);
        assert_eq!(
            fs::metadata(store.trust_path())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        let original = fs::read(store.trust_path()).unwrap();
        let retry = store
            .apply_trust_policy_with_root(&first_policy, &first_signature, &root.public)
            .unwrap();
        assert_eq!(retry.action, TrustPolicyAction::AlreadyCurrent);
        assert_eq!(fs::read(store.trust_path()).unwrap(), original);

        let (collision_policy, collision_signature) =
            signed_policy(&root, 1, &[&old, &new], vec![]);
        assert!(matches!(
            store.apply_trust_policy_with_root(
                &collision_policy,
                &collision_signature,
                &root.public
            ),
            Err(ReleaseError::TrustPolicySequenceCollision)
        ));
        assert_eq!(fs::read(store.trust_path()).unwrap(), original);

        let (overlap_policy, overlap_signature) = signed_policy(&root, 2, &[&old, &new], vec![]);
        assert_eq!(
            store
                .apply_trust_policy_with_root(&overlap_policy, &overlap_signature, &root.public,)
                .unwrap()
                .action,
            TrustPolicyAction::Update
        );
        let (revoked_policy, revoked_signature) =
            signed_policy(&root, 3, &[&new], vec![old_id.clone()]);
        let revoked = store
            .apply_trust_policy_with_root(&revoked_policy, &revoked_signature, &root.public)
            .unwrap();
        assert_eq!(revoked.state.revoked_release_key_ids, vec![old_id]);
        let final_bytes = fs::read(store.trust_path()).unwrap();

        assert!(matches!(
            store.apply_trust_policy_with_root(&overlap_policy, &overlap_signature, &root.public),
            Err(ReleaseError::TrustPolicyRollback)
        ));
        let (unrevoked_policy, unrevoked_signature) =
            signed_policy(&root, 4, &[&old, &new], vec![]);
        assert!(matches!(
            store.apply_trust_policy_with_root(
                &unrevoked_policy,
                &unrevoked_signature,
                &root.public
            ),
            Err(ReleaseError::TrustPolicyUnrevokesKey)
        ));
        let (removed_policy, removed_signature) = signed_policy(&root, 4, &[&new], vec![]);
        assert!(matches!(
            store.apply_trust_policy_with_root(&removed_policy, &removed_signature, &root.public),
            Err(ReleaseError::TrustPolicyUnrevokesKey)
        ));
        assert_eq!(fs::read(store.trust_path()).unwrap(), final_bytes);
    }

    #[test]
    fn installed_policy_rejects_unsafe_or_noncanonical_state() {
        let directory = tempfile::tempdir().unwrap();
        let state = directory.path().join("state");
        let store = crate::InstalledReleaseStore::new(&state);
        let root = keys();
        let release = keys();
        let (policy, signature) = signed_policy(&root, 1, &[&release], vec![]);
        store
            .apply_trust_policy_with_root(&policy, &signature, &root.public)
            .unwrap();

        let bytes = fs::read(store.trust_path()).unwrap();
        fs::write(
            store.trust_path(),
            serde_json::to_vec(&serde_json::from_slice::<InstalledReleaseTrust>(&bytes).unwrap())
                .unwrap(),
        )
        .unwrap();
        assert!(matches!(
            store.read_trust_unlocked_with_root(&root.public),
            Err(ReleaseError::NonCanonicalInstalledTrust)
        ));

        fs::remove_file(store.trust_path()).unwrap();
        let outside = directory.path().join("outside");
        fs::write(&outside, bytes).unwrap();
        symlink(&outside, store.trust_path()).unwrap();
        assert!(matches!(
            store.read_trust_unlocked_with_root(&root.public),
            Err(ReleaseError::UnsafeInstalledState)
        ));
    }

    #[test]
    fn removed_active_key_requires_permanent_revocation() {
        let root = keys();
        let old = keys();
        let new = keys();
        let (first_policy, first_signature) = signed_policy(&root, 1, &[&old, &new], vec![]);
        let (second_policy, second_signature) = signed_policy(&root, 2, &[&new], vec![]);
        let first = InstalledReleaseTrust {
            schema_version: INSTALLED_RELEASE_TRUST_SCHEMA_VERSION,
            policy: parse_trust_policy(&first_policy).unwrap(),
            signature: parse_trust_signature(&first_signature).unwrap(),
        };
        let second = InstalledReleaseTrust {
            schema_version: INSTALLED_RELEASE_TRUST_SCHEMA_VERSION,
            policy: parse_trust_policy(&second_policy).unwrap(),
            signature: parse_trust_signature(&second_signature).unwrap(),
        };
        assert!(matches!(
            evaluate_trust_update(Some(&first), &second),
            Err(ReleaseError::TrustPolicyRemovesKeyWithoutRevocation)
        ));
    }
}
