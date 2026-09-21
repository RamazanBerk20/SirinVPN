use super::*;

/// Verify an incoming root-signed policy against a protected installed record
/// without writing state. SSH installers bind the exact inspected record to
/// their later root transaction before executing the candidate artifact.
pub fn verify_trust_policy_update(
    installed: Option<&[u8]>,
    policy: &[u8],
    signature: &[u8],
) -> Result<VerifiedReleaseTrustPolicy, ReleaseError> {
    verify_update_with_root(installed, policy, signature, BUNDLED_RELEASE_TRUST_ROOT_PEM)
}

fn verify_update_with_root(
    installed: Option<&[u8]>,
    policy: &[u8],
    signature: &[u8],
    root: &str,
) -> Result<VerifiedReleaseTrustPolicy, ReleaseError> {
    let verified = verify_trust_policy(policy, signature, root)?;
    let current = installed
        .map(|bytes| {
            check_size(
                bytes,
                MAX_INSTALLED_TRUST_BYTES,
                ReleaseError::InstalledTrustSize,
            )?;
            let trust: InstalledReleaseTrust =
                serde_json::from_slice(bytes).map_err(|_| ReleaseError::InvalidInstalledTrust)?;
            validate_installed_trust(&trust, root)?;
            if canonical_json(&trust)? != bytes {
                return Err(ReleaseError::NonCanonicalInstalledTrust);
            }
            Ok(trust)
        })
        .transpose()?;
    let candidate = InstalledReleaseTrust {
        schema_version: INSTALLED_RELEASE_TRUST_SCHEMA_VERSION,
        policy: verified.policy.clone(),
        signature: parse_trust_signature(signature)?,
    };
    evaluate_trust_update(current.as_ref(), &candidate)?;
    Ok(verified)
}

#[cfg(test)]
mod tests;
