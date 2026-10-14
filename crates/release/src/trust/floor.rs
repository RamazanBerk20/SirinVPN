use super::*;
use crate::{InstalledReleaseStore, ReleaseChannel, ReleaseManifest};

/// Read-only snapshot of this device's own protected release state.
///
/// A fresh VPS has no installed policy or receipt, so on its own it would
/// accept any policy the bundled root ever signed, including one that still
/// lists a since-revoked release key, and any older signed release. The device
/// establishing that VPS must not place it below what the device itself
/// already trusts. An empty floor keeps the bundled-root-only behavior.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct LocalReleaseFloor {
    trust: Option<Vec<u8>>,
    highest_accepted: Option<AcceptedRelease>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct AcceptedRelease {
    channel: ReleaseChannel,
    sequence: u64,
    manifest_sha256: String,
}

impl LocalReleaseFloor {
    /// The Linux package keeps its state in the root-private system store.
    /// Any other account cannot read it and gets an empty floor.
    pub fn system() -> Result<Self, ReleaseError> {
        #[cfg(unix)]
        if nix::unistd::Uid::effective().is_root() {
            return InstalledReleaseStore::system().release_floor();
        }
        Ok(Self::default())
    }

    pub fn is_empty(&self) -> bool {
        self.trust.is_none() && self.highest_accepted.is_none()
    }

    /// Canonical installed trust record, in the same form a VPS stores it.
    pub fn trust_record(&self) -> Option<&[u8]> {
        self.trust.as_deref()
    }

    /// Verify a served policy against the bundled root and require it to be
    /// at least as new as, and keep every revocation of, this device's policy.
    pub fn verify_trust_policy(
        &self,
        policy: &[u8],
        signature: &[u8],
    ) -> Result<VerifiedReleaseTrustPolicy, ReleaseError> {
        self.verify_trust_policy_with_root(policy, signature, BUNDLED_RELEASE_TRUST_ROOT_PEM)
    }

    pub(crate) fn verify_trust_policy_with_root(
        &self,
        policy: &[u8],
        signature: &[u8],
        root_public_key_pem: &str,
    ) -> Result<VerifiedReleaseTrustPolicy, ReleaseError> {
        verification::verify_update_with_root(
            self.trust_record(),
            policy,
            signature,
            root_public_key_pem,
        )
    }

    /// Apply this device's release high watermark on the same track. Another
    /// channel has an independent sequence, exactly as for local updates.
    pub fn verify_release(
        &self,
        manifest: &ReleaseManifest,
        manifest_sha256: &str,
    ) -> Result<(), ReleaseError> {
        let Some(accepted) = &self.highest_accepted else {
            return Ok(());
        };
        if accepted.channel != manifest.channel {
            return Ok(());
        }
        match manifest.release_sequence.cmp(&accepted.sequence) {
            std::cmp::Ordering::Less => Err(ReleaseError::BelowHighestAcceptedRelease),
            std::cmp::Ordering::Equal if manifest_sha256 != accepted.manifest_sha256 => {
                Err(ReleaseError::ReleaseSequenceCollision)
            }
            _ => Ok(()),
        }
    }
}

impl InstalledReleaseStore {
    /// Read this store's trust record and release high watermark without
    /// changing them. A store that was never created yields an empty floor.
    pub fn release_floor(&self) -> Result<LocalReleaseFloor, ReleaseError> {
        self.release_floor_with_root(BUNDLED_RELEASE_TRUST_ROOT_PEM)
    }

    pub(crate) fn release_floor_with_root(
        &self,
        root_public_key_pem: &str,
    ) -> Result<LocalReleaseFloor, ReleaseError> {
        if !self.validate_existing_directory()? {
            return Ok(LocalReleaseFloor::default());
        }
        let lock = self.open_lock()?;
        FileExt::lock_shared(&lock)?;
        let result = (|| {
            let trust = self
                .read_trust_unlocked_with_root(root_public_key_pem)?
                .map(|trust| canonical_json(&trust))
                .transpose()?;
            let highest_accepted = self.read_receipt_unlocked()?.map(|receipt| {
                let highest = receipt.highest_accepted_release;
                AcceptedRelease {
                    channel: highest.manifest.channel,
                    sequence: highest.manifest.release_sequence,
                    manifest_sha256: highest.signature.manifest_sha256,
                }
            });
            Ok(LocalReleaseFloor {
                trust,
                highest_accepted,
            })
        })();
        crate::installed_release::finish_locked(lock, result)
    }
}

#[cfg(test)]
mod tests;
