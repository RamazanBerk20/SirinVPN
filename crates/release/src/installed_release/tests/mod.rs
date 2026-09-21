use super::*;

use crate::{
    ReleaseChannel, SchemaRange, StateCompatibility, build_manifest, build_trust_policy,
    encode_manifest, encode_trust_policy, generate_signing_keypair, public_key_id, sign_manifest,
    sign_trust_policy,
};

use std::os::unix::fs::{PermissionsExt, symlink};

use zeroize::Zeroizing;

const TARGET: &str = "x86_64-unknown-linux-gnu";

struct TestKeys {
    private: Zeroizing<String>,
    public: String,
}

struct TestRelease {
    directory: PathBuf,
    manifest: Vec<u8>,
    signature: Vec<u8>,
}

fn test_keys() -> TestKeys {
    let (private, public) = generate_signing_keypair().unwrap();
    TestKeys { private, public }
}

fn compatibility() -> Vec<StateCompatibility> {
    vec![
        StateCompatibility {
            state: "linux_release_receipt".to_owned(),
            reads: SchemaRange {
                minimum: 1,
                maximum: 1,
            },
            writes: SchemaRange {
                minimum: 1,
                maximum: 1,
            },
        },
        StateCompatibility {
            state: "linux_release_transaction".to_owned(),
            reads: SchemaRange {
                minimum: 1,
                maximum: 1,
            },
            writes: SchemaRange {
                minimum: 1,
                maximum: 1,
            },
        },
        StateCompatibility {
            state: crate::LINUX_RELEASE_TRUST_STATE_NAME.to_owned(),
            reads: SchemaRange {
                minimum: 1,
                maximum: 1,
            },
            writes: SchemaRange {
                minimum: 1,
                maximum: 1,
            },
        },
    ]
}

fn release(
    root: &Path,
    keys: &TestKeys,
    version: &str,
    sequence: u64,
    content: &str,
) -> TestRelease {
    release_with_compatibility(root, keys, version, sequence, content, compatibility())
}

fn release_with_compatibility(
    root: &Path,
    keys: &TestKeys,
    version: &str,
    sequence: u64,
    content: &str,
    state_compatibility: Vec<StateCompatibility>,
) -> TestRelease {
    let directory = root.join(format!("release-{sequence}-{content}"));
    fs::create_dir(&directory).unwrap();
    let artifact_path = directory.join(format!("SirinVPN_{version}_amd64.AppImage"));
    fs::write(&artifact_path, content).unwrap();
    let artifact =
        ReleaseArtifact::from_path(ArtifactKind::LinuxAppImage, TARGET, &artifact_path).unwrap();
    let manifest = build_manifest(
        version,
        sequence,
        ReleaseChannel::Stable,
        false,
        vec![artifact],
        state_compatibility,
    )
    .unwrap();
    let manifest = encode_manifest(&manifest).unwrap();
    let signature = sign_manifest(&manifest, &keys.private).unwrap();
    TestRelease {
        directory,
        manifest,
        signature,
    }
}

fn plan(
    store: &InstalledReleaseStore,
    release: &TestRelease,
    public_key: &str,
    allow_rollback: bool,
) -> Result<InstallationDecision, ReleaseError> {
    store.plan_installation(
        &release.manifest,
        &release.signature,
        public_key,
        &release.directory,
        ArtifactKind::LinuxAppImage,
        TARGET,
        allow_rollback,
    )
}

fn commit(
    store: &InstalledReleaseStore,
    release: &TestRelease,
    public_key: &str,
    allow_rollback: bool,
) -> Result<InstallationDecision, ReleaseError> {
    store.commit_installation(
        &release.manifest,
        &release.signature,
        public_key,
        &release.directory,
        ArtifactKind::LinuxAppImage,
        TARGET,
        allow_rollback,
    )
}

fn apply_trust(
    store: &InstalledReleaseStore,
    root: &TestKeys,
    sequence: u64,
    active: &[&TestKeys],
    revoked: Vec<String>,
) {
    let policy = build_trust_policy(
        sequence,
        active.iter().map(|keys| keys.public.clone()).collect(),
        revoked,
    )
    .unwrap();
    let policy = encode_trust_policy(&policy).unwrap();
    let signature = sign_trust_policy(&policy, &root.private).unwrap();
    store
        .apply_trust_policy_with_root(&policy, &signature, &root.public)
        .unwrap();
}

mod absent_state_plans_without_writing_and_first_commit_is_private;
mod same_signed_release_can_rebind_to_another_declared_artifact;
mod windows;
