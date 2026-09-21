use super::*;
use crate::{
    ReleaseChannel, SchemaRange, StateCompatibility, build_manifest, build_trust_policy,
    encode_manifest, encode_trust_policy, generate_signing_keypair, sign_manifest,
    sign_trust_policy,
};
use std::fs;

struct Fixture {
    root: tempfile::TempDir,
    store: InstalledReleaseStore,
    installed: PathBuf,
    root_public: String,
    signing: zeroize::Zeroizing<String>,
    kind: ArtifactKind,
}
struct Release {
    manifest: Vec<u8>,
    signature: Vec<u8>,
    directory: PathBuf,
    kind: ArtifactKind,
}
impl Release {
    fn bundle(&self) -> ClientReleaseBundle<'_> {
        ClientReleaseBundle {
            manifest: &self.manifest,
            signature: &self.signature,
            artifact_directory: &self.directory,
            kind: self.kind,
            target: if self.kind == ArtifactKind::AndroidApk {
                "aarch64-linux-android"
            } else {
                "x86_64-unknown-linux-gnu"
            },
        }
    }
    fn path(&self) -> PathBuf {
        self.directory
            .join(if self.kind == ArtifactKind::AndroidApk {
                "vpn.apk"
            } else {
                "vpn.AppImage"
            })
    }
}
impl Fixture {
    fn new(kind: ArtifactKind) -> Self {
        let root = tempfile::tempdir().unwrap();
        let (root_private, root_public) = generate_signing_keypair().unwrap();
        let (signing, public) = generate_signing_keypair().unwrap();
        let store = InstalledReleaseStore::new(root.path().join("state"));
        let policy =
            encode_trust_policy(&build_trust_policy(1, vec![public], vec![]).unwrap()).unwrap();
        let signature = sign_trust_policy(&policy, &root_private).unwrap();
        store
            .apply_trust_policy_with_root(&policy, &signature, &root_public)
            .unwrap();
        let installed = root.path().join("installed");
        Self {
            root,
            store,
            installed,
            root_public,
            signing,
            kind,
        }
    }
    fn release(&self, n: u8) -> Release {
        let directory = self.root.path().join(format!("release-{n}"));
        fs::create_dir(&directory).unwrap();
        let mut release = Release {
            manifest: Vec::new(),
            signature: Vec::new(),
            directory,
            kind: self.kind,
        };
        fs::write(release.path(), [n; 64]).unwrap();
        let artifact =
            ReleaseArtifact::from_path(self.kind, release.bundle().target, &release.path())
                .unwrap();
        let states = [
            "linux_release_receipt",
            "linux_release_trust",
            "client_release_transaction",
            "android_profile_registry",
        ]
        .into_iter()
        .map(|state| StateCompatibility {
            state: state.into(),
            reads: SchemaRange {
                minimum: 1,
                maximum: 1,
            },
            writes: SchemaRange {
                minimum: 1,
                maximum: 1,
            },
        })
        .collect();
        release.manifest = encode_manifest(
            &build_manifest(
                format!("1.0.{n}"),
                u64::from(n),
                ReleaseChannel::Stable,
                false,
                vec![artifact],
                states,
            )
            .unwrap(),
        )
        .unwrap();
        release.signature = sign_manifest(&release.manifest, &self.signing).unwrap();
        release
    }
    fn prepare(
        &self,
        release: &Release,
        version: &str,
    ) -> Result<PreparedClientRelease, ReleaseError> {
        self.store.prepare_client_with_root(
            &release.bundle(),
            &self.installed,
            version,
            &self.root_public,
        )
    }
    fn bind(&self, release: &Release) {
        fs::copy(release.path(), &self.installed).unwrap();
        assert!(self.prepare(release, "1.0.1").unwrap().baseline_bound);
    }
    fn complete(&self) -> Result<bool, ReleaseError> {
        self.store
            .finish_client_with_root(&self.installed, &self.root_public)
    }
}

#[test]
fn baseline_requires_exact_signed_installed_bytes_and_running_version() {
    let f = Fixture::new(ArtifactKind::AndroidApk);
    let first = f.release(1);
    fs::write(&f.installed, [99; 64]).unwrap();
    assert!(matches!(
        f.prepare(&first, "1.0.1"),
        Err(ReleaseError::ClientBaselineRequired)
    ));
    fs::copy(first.path(), &f.installed).unwrap();
    assert!(matches!(
        f.prepare(&first, "1.0.0"),
        Err(ReleaseError::ClientBaselineRequired)
    ));
    assert!(f.store.read_receipt_unlocked().unwrap().is_none());
    f.bind(&first);
    assert_eq!(
        f.store
            .read_receipt_unlocked()
            .unwrap()
            .unwrap()
            .active_release
            .manifest
            .release_sequence,
        1
    );
}

#[test]
fn android_receipt_waits_for_the_installed_apk_and_retries_after_restart() {
    let f = Fixture::new(ArtifactKind::AndroidApk);
    let first = f.release(1);
    let next = f.release(2);
    f.bind(&first);
    let pending = f.prepare(&next, "1.0.1").unwrap();
    assert!(!pending.baseline_bound);
    assert!(!f.complete().unwrap());
    assert!(matches!(
        f.prepare(&next, "1.0.1"),
        Err(ReleaseError::ClientUpdatePending)
    ));
    assert_eq!(
        f.store
            .read_receipt_unlocked()
            .unwrap()
            .unwrap()
            .active_release
            .manifest
            .release_sequence,
        1
    );
    fs::copy(&pending.artifact, &f.installed).unwrap();
    assert!(f.store.cancel_client_release(&f.installed).is_err());
    assert!(f.complete().unwrap());
    assert!(!f.complete().unwrap());
    assert_eq!(
        f.store.inspect_client_release().unwrap().pending_version,
        None
    );
    assert_eq!(
        f.store
            .read_receipt_unlocked()
            .unwrap()
            .unwrap()
            .active_release
            .manifest
            .release_sequence,
        2
    );
}

#[test]
fn native_installer_independently_binds_root_journal_target_cache_and_installed_bytes() {
    let f = Fixture::new(ArtifactKind::AndroidApk);
    let first = f.release(1);
    let next = f.release(2);
    f.bind(&first);
    let pending = f.prepare(&next, "1.0.1").unwrap();
    let verify = |path: &Path, target: &str, root: &str| {
        f.store.verify_pending_client_with_root(
            &f.installed,
            path,
            ArtifactKind::AndroidApk,
            target,
            root,
        )
    };
    assert_eq!(
        verify(&pending.artifact, "aarch64-linux-android", &f.root_public)
            .unwrap()
            .active_release_version,
        "1.0.2"
    );
    // The release-source copy has identical bytes but is outside the protected
    // current transaction cache. Native installation must reject that path.
    assert!(verify(&next.path(), "aarch64-linux-android", &f.root_public).is_err());
    assert!(verify(&pending.artifact, "x86_64-linux-android", &f.root_public).is_err());
    let (_, another_root) = generate_signing_keypair().unwrap();
    assert!(verify(&pending.artifact, "aarch64-linux-android", &another_root).is_err());
    fs::write(&f.installed, [9; 64]).unwrap();
    assert!(verify(&pending.artifact, "aarch64-linux-android", &f.root_public).is_err());
    fs::copy(first.path(), &f.installed).unwrap();
    fs::write(&pending.artifact, [9; 64]).unwrap();
    assert!(verify(&pending.artifact, "aarch64-linux-android", &f.root_public).is_err());
}

#[test]
fn cancelled_install_preserves_receipt_and_modified_cache_preserves_journal() {
    let f = Fixture::new(ArtifactKind::AndroidApk);
    let first = f.release(1);
    let next = f.release(2);
    f.bind(&first);
    f.prepare(&next, "1.0.1").unwrap();
    f.store.cancel_client_release(&f.installed).unwrap();
    assert!(f.store.read_client_journal().unwrap().is_none());
    let pending = f.prepare(&next, "1.0.1").unwrap();
    fs::write(&pending.artifact, [9; 64]).unwrap();
    assert!(f.complete().is_err());
    assert!(
        f.store
            .state_directory()
            .join("client-transaction.json")
            .exists()
    );
    assert_eq!(fs::read(&f.installed).unwrap(), [1; 64]);
}

#[test]
fn appimage_rollback_preserves_high_watermark_and_rejects_silent_replay() {
    let f = Fixture::new(ArtifactKind::LinuxAppImage);
    let first = f.release(1);
    let next = f.release(2);
    f.bind(&first);
    let pending = f.prepare(&next, "1.0.1").unwrap();
    f.store
        .replace_appimage_with_root(
            &f.installed,
            |path, _| {
                fs::copy(path, &f.installed)?;
                Ok(())
            },
            &f.root_public,
        )
        .unwrap();
    assert_eq!(
        crate::digest_artifact(&f.installed).unwrap().1,
        pending.state.active_artifact.sha256
    );
    assert!(f.prepare(&first, "1.0.2").is_err());
    let rollback = f
        .store
        .prepare_rollback_with_root(&f.installed, &f.root_public)
        .unwrap();
    f.store
        .replace_appimage_with_root(
            &f.installed,
            |path, _| {
                fs::copy(path, &f.installed)?;
                Ok(())
            },
            &f.root_public,
        )
        .unwrap();
    assert_eq!(rollback.state.highest_accepted_release_sequence, 2);
    assert_eq!(fs::read(&f.installed).unwrap(), [1; 64]);
    assert_eq!(
        f.store
            .read_receipt_unlocked()
            .unwrap()
            .unwrap()
            .highest_accepted_release
            .manifest
            .release_sequence,
        2
    );
}

#[test]
fn replacement_interruption_before_or_after_rename_has_unambiguous_recovery() {
    for after_replace in [false, true] {
        let f = Fixture::new(ArtifactKind::LinuxAppImage);
        let first = f.release(1);
        let next = f.release(2);
        f.bind(&first);
        f.prepare(&next, "1.0.1").unwrap();
        let result = f.store.replace_appimage_with_root(
            &f.installed,
            |path, _| {
                if after_replace {
                    fs::copy(path, &f.installed)?;
                }
                Err(std::io::Error::other("injected interruption").into())
            },
            &f.root_public,
        );
        assert!(result.is_err());
        assert_eq!(f.complete().unwrap(), after_replace);
        if !after_replace {
            f.store.cancel_client_release(&f.installed).unwrap();
        }
        assert!(f.store.read_client_journal().unwrap().is_none());
        assert_eq!(
            fs::read(&f.installed).unwrap(),
            [if after_replace { 2 } else { 1 }; 64]
        );
    }
}

#[test]
fn incompatible_state_and_changed_signed_artifact_do_not_prepare_installation() {
    let f = Fixture::new(ArtifactKind::AndroidApk);
    let first = f.release(1);
    let mut next = f.release(2);
    f.bind(&first);
    let mut manifest = crate::parse_manifest(&next.manifest).unwrap();
    manifest
        .state_compatibility
        .iter_mut()
        .find(|state| state.state == "android_profile_registry")
        .unwrap()
        .writes
        .maximum = 2;
    next.manifest = encode_manifest(&manifest).unwrap();
    next.signature = sign_manifest(&next.manifest, &f.signing).unwrap();
    assert!(f.prepare(&next, "1.0.1").is_err());
    fs::write(next.path(), [99; 64]).unwrap();
    assert!(f.prepare(&next, "1.0.1").is_err());
    assert!(f.store.read_client_journal().unwrap().is_none());
}
