use super::*;

use crate::{
    ReleaseChannel, SchemaRange, StateCompatibility, build_manifest, build_trust_policy,
    encode_manifest, encode_trust_policy, generate_signing_keypair, parse_manifest, public_key_id,
    sign_manifest, sign_trust_policy,
};

use std::{cell::RefCell, collections::HashSet};

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
    artifact: ReleaseArtifact,
}

#[derive(Default)]
struct FakePackageManager {
    installed_version: RefCell<String>,
    events: RefCell<Vec<String>>,
    fail_install_once: RefCell<HashSet<String>>,
    fail_health_once: RefCell<HashSet<String>>,
    receipt_path: RefCell<Option<PathBuf>>,
    observed_health_receipts: RefCell<Vec<(String, String)>>,
}

impl FakePackageManager {
    fn installed(version: &str) -> Self {
        Self {
            installed_version: RefCell::new(version.to_owned()),
            ..Self::default()
        }
    }

    fn fail_next_install(&self, version: &str) {
        self.fail_install_once
            .borrow_mut()
            .insert(version.to_owned());
    }

    fn fail_next_health(&self, version: &str) {
        self.fail_health_once
            .borrow_mut()
            .insert(version.to_owned());
    }

    fn observe_receipt(&self, path: PathBuf) {
        *self.receipt_path.borrow_mut() = Some(path);
    }

    fn events(&self) -> Vec<String> {
        self.events.borrow().clone()
    }
}

impl DebianPackageManager for FakePackageManager {
    fn lock_network_operations(&self) -> Result<Box<dyn Send>, ReleaseError> {
        self.events.borrow_mut().push("lock-network".to_owned());
        Ok(Box::new(()))
    }

    fn preflight_candidate(
        &self,
        package: &Path,
        expected_version: &str,
        target: &str,
    ) -> Result<(), ReleaseError> {
        self.events
            .borrow_mut()
            .push(format!("preflight:{expected_version}"));
        let metadata =
            fs::symlink_metadata(package).map_err(|_| ReleaseError::InvalidDebianPackage)?;
        if target != TARGET
            || !metadata.file_type().is_file()
            || metadata.permissions().mode() & 0o777 != 0o600
        {
            return Err(ReleaseError::InvalidDebianPackage);
        }
        Ok(())
    }

    fn install_package(&self, _package: &Path, expected_version: &str) -> Result<(), ReleaseError> {
        self.events
            .borrow_mut()
            .push(format!("install:{expected_version}"));
        if self.fail_install_once.borrow_mut().remove(expected_version) {
            return Err(ReleaseError::DebianPackageOperation);
        }
        *self.installed_version.borrow_mut() = expected_version.to_owned();
        Ok(())
    }

    fn check_installed_health(&self, expected_version: &str) -> Result<(), ReleaseError> {
        self.events
            .borrow_mut()
            .push(format!("health:{expected_version}"));
        if let Some(receipt_path) = self.receipt_path.borrow().as_ref() {
            let receipt: InstalledReleaseReceipt =
                serde_json::from_slice(&fs::read(receipt_path).unwrap()).unwrap();
            self.observed_health_receipts.borrow_mut().push((
                expected_version.to_owned(),
                receipt.active_release.manifest.release_version,
            ));
        }
        if self.fail_health_once.borrow_mut().remove(expected_version)
            || self.installed_version.borrow().as_str() != expected_version
        {
            return Err(ReleaseError::DebianPackageHealth);
        }
        Ok(())
    }
}

fn keys() -> TestKeys {
    let (private, public) = generate_signing_keypair().unwrap();
    TestKeys { private, public }
}

fn compatibility() -> Vec<StateCompatibility> {
    [
        "linux_release_receipt",
        TRANSACTION_STATE_NAME,
        crate::LINUX_RELEASE_TRUST_STATE_NAME,
    ]
    .into_iter()
    .map(|state| StateCompatibility {
        state: state.to_owned(),
        reads: SchemaRange {
            minimum: 1,
            maximum: 1,
        },
        writes: SchemaRange {
            minimum: 1,
            maximum: 1,
        },
    })
    .collect()
}

fn release(root: &Path, keys: &TestKeys, version: &str, sequence: u64) -> TestRelease {
    release_with_compatibility(root, keys, version, sequence, compatibility())
}

fn release_with_compatibility(
    root: &Path,
    keys: &TestKeys,
    version: &str,
    sequence: u64,
    state_compatibility: Vec<StateCompatibility>,
) -> TestRelease {
    let directory = root.join(format!("release-{sequence}"));
    fs::create_dir(&directory).unwrap();
    let package = directory.join(format!("SirinVPN_{version}_amd64.deb"));
    fs::write(&package, format!("test Debian package {version}")).unwrap();
    let artifact = ReleaseArtifact::from_path(ArtifactKind::LinuxDeb, TARGET, &package).unwrap();
    let manifest = build_manifest(
        version,
        sequence,
        ReleaseChannel::Stable,
        false,
        vec![artifact.clone()],
        state_compatibility,
    )
    .unwrap();
    let manifest = encode_manifest(&manifest).unwrap();
    let signature = sign_manifest(&manifest, &keys.private).unwrap();
    TestRelease {
        directory,
        manifest,
        signature,
        artifact,
    }
}

fn initialize(store: &InstalledReleaseStore, release: &TestRelease, public_key: &str) {
    store
        .commit_installation(
            &release.manifest,
            &release.signature,
            public_key,
            &release.directory,
            ArtifactKind::LinuxDeb,
            TARGET,
            false,
        )
        .unwrap();
}

fn install(
    store: &InstalledReleaseStore,
    release: &TestRelease,
    public_key: &str,
    manager: &FakePackageManager,
) -> Result<InstallationDecision, ReleaseError> {
    install_allowing_rollback(store, release, public_key, false, manager)
}

fn install_allowing_rollback(
    store: &InstalledReleaseStore,
    release: &TestRelease,
    public_key: &str,
    allow_rollback: bool,
    manager: &FakePackageManager,
) -> Result<InstallationDecision, ReleaseError> {
    store.install_debian_with(
        &release.manifest,
        &release.signature,
        public_key,
        &release.directory,
        TARGET,
        allow_rollback,
        manager,
    )
}

fn apply_trust(
    store: &InstalledReleaseStore,
    root: &TestKeys,
    sequence: u64,
    active: &[&TestKeys],
) {
    let policy = build_trust_policy(
        sequence,
        active.iter().map(|keys| keys.public.clone()).collect(),
        vec![],
    )
    .unwrap();
    let policy = encode_trust_policy(&policy).unwrap();
    let signature = sign_trust_policy(&policy, &root.private).unwrap();
    store
        .apply_trust_policy_with_root(&policy, &signature, &root.public)
        .unwrap();
}

fn cached_files(store: &InstalledReleaseStore) -> Vec<String> {
    let mut names = fs::read_dir(store.package_directory())
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect::<Vec<_>>();
    names.sort();
    names
}

mod successful_update_commits_receipt_only_after_candidate_health;
