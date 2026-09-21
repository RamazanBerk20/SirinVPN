use super::*;
use crate::{
    ReleaseArtifact, ReleaseChannel, SchemaRange, StateCompatibility, build_manifest,
    build_trust_policy, encode_manifest, encode_trust_policy, generate_signing_keypair,
    sign_manifest, sign_trust_policy,
};
use std::{
    cell::{Cell, RefCell},
    fs,
    path::PathBuf,
};

const TARGET: &str = "x86_64-unknown-linux-gnu";

struct Release {
    manifest: Vec<u8>,
    signature: Vec<u8>,
    directory: PathBuf,
}
impl Release {
    fn bundle(&self) -> ServerReleaseBundle<'_> {
        ServerReleaseBundle {
            manifest: &self.manifest,
            signature: &self.signature,
            artifact_directory: &self.directory,
            target: TARGET,
        }
    }
}

struct Host {
    binary: PathBuf,
    calls: RefCell<Vec<String>>,
    fail_health_for: Cell<Option<u8>>,
    cut_at: Cell<Option<usize>>,
    schema: Cell<u16>,
}
impl Host {
    fn call(&self, name: &str) {
        self.calls.borrow_mut().push(name.to_owned());
        if self.cut_at.get() == Some(self.calls.borrow().len()) {
            panic!("simulated power loss");
        }
    }
}
impl ServerReleaseHost for Host {
    fn lock(&self) -> Result<Box<dyn Send>, ReleaseError> {
        Ok(Box::new(()))
    }
    fn installed_binary(&self) -> &Path {
        &self.binary
    }
    fn preflight(
        &self,
        _executable: &Path,
        manifest: &ReleaseManifest,
    ) -> Result<(), ReleaseError> {
        self.call("preflight");
        let state = manifest
            .state_compatibility
            .iter()
            .find(|v| v.state == "server_authorization")
            .unwrap();
        if self.schema.get() > state.reads.maximum {
            return Err(ReleaseError::ForwardIncompatible(state.state.clone()));
        }
        Ok(())
    }
    fn stop(&self) -> Result<(), ReleaseError> {
        self.call("stop");
        Ok(())
    }
    fn replace(&self, executable: &Path) -> Result<(), ReleaseError> {
        fs::copy(executable, &self.binary)?;
        self.call("replace");
        Ok(())
    }
    fn start(&self) -> Result<(), ReleaseError> {
        self.call("start");
        Ok(())
    }
    fn health(&self) -> Result<(), ReleaseError> {
        self.call("health");
        if self.fail_health_for.get() == fs::read(&self.binary)?.first().copied() {
            return Err(ReleaseError::ServerOperation("health"));
        }
        Ok(())
    }
    fn complete(&self) -> Result<(), ReleaseError> {
        self.call("complete");
        Ok(())
    }
}

struct Fixture {
    root: tempfile::TempDir,
    signing: zeroize::Zeroizing<String>,
    root_public: String,
    root_private: zeroize::Zeroizing<String>,
    store: InstalledReleaseStore,
    host: Host,
}
impl Fixture {
    fn new() -> Self {
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
        let binary = root.path().join("installed");
        let host = Host {
            binary,
            calls: RefCell::default(),
            fail_health_for: Cell::new(None),
            cut_at: Cell::new(None),
            schema: Cell::new(1),
        };
        Self {
            root,
            signing,
            root_public,
            root_private,
            store,
            host,
        }
    }
    fn release(&self, sequence: u8) -> Release {
        let directory = self.root.path().join(format!("release-{sequence}"));
        fs::create_dir(&directory).unwrap();
        let path = directory.join("sirinvpn-server");
        fs::write(&path, [sequence; 32]).unwrap();
        let artifact = ReleaseArtifact::from_path(ArtifactKind::ServerElf, TARGET, &path).unwrap();
        let states = [
            "linux_release_receipt",
            "linux_release_trust",
            "server_authorization",
            "server_handoff_guard",
            "server_maintenance_guard",
            "server_release_transaction",
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
        .collect();
        let manifest = encode_manifest(
            &build_manifest(
                format!("1.0.{sequence}"),
                u64::from(sequence),
                ReleaseChannel::Stable,
                true,
                vec![artifact],
                states,
            )
            .unwrap(),
        )
        .unwrap();
        let signature = sign_manifest(&manifest, &self.signing).unwrap();
        Release {
            manifest,
            signature,
            directory,
        }
    }
    fn adopt(&self, release: &Release) {
        fs::copy(release.directory.join("sirinvpn-server"), &self.host.binary).unwrap();
        self.store
            .adopt_server_with_root(&release.bundle(), &self.host, &self.root_public)
            .unwrap();
        self.host.calls.borrow_mut().clear();
    }
    fn update(&self, release: &Release) -> Result<InstallationDecision, ReleaseError> {
        self.store
            .install_server_with_root(&release.bundle(), &self.host, &self.root_public)
    }
    fn installed(&self) -> u8 {
        fs::read(&self.host.binary).unwrap()[0]
    }
}

#[test]
fn requires_exact_authenticated_baseline_and_signed_candidate_before_execution() {
    let fixture = Fixture::new();
    let release = fixture.release(1);
    fs::write(&fixture.host.binary, b"unknown").unwrap();
    assert!(matches!(
        fixture.store.adopt_server_with_root(
            &release.bundle(),
            &fixture.host,
            &fixture.root_public
        ),
        Err(ReleaseError::ServerInstalledMismatch)
    ));
    assert!(fixture.host.calls.borrow().is_empty());
    assert!(fixture.store.inspect().unwrap().is_none());
    fixture.adopt(&release);
    let candidate = fixture.release(2);
    fs::write(candidate.directory.join("sirinvpn-server"), b"tampered").unwrap();
    assert!(fixture.update(&candidate).is_err());
    assert!(fixture.host.calls.borrow().is_empty());
    assert_eq!(fixture.installed(), 1);
}

#[test]
fn upgrade_and_explicit_rollback_keep_high_watermark_and_current_authorization() {
    let fixture = Fixture::new();
    fixture.adopt(&fixture.release(1));
    assert_eq!(
        fixture.update(&fixture.release(2)).unwrap().action,
        InstallationDecisionKind::Upgrade
    );
    let rolled = fixture
        .store
        .rollback_server_with_root(&fixture.host, &fixture.root_public)
        .unwrap();
    assert_eq!(rolled.action, InstallationDecisionKind::Rollback);
    assert_eq!(rolled.state.active_release_sequence, 1);
    assert_eq!(rolled.state.highest_accepted_release_sequence, 2);
    assert_eq!(fixture.installed(), 1);
    assert_eq!(fixture.host.schema.get(), 1);
    assert_eq!(
        fs::read_dir(fixture.store.package_directory())
            .unwrap()
            .count(),
        2
    );
}

#[test]
fn unhealthy_candidate_restores_previous_and_does_not_accept_failed_sequence() {
    let fixture = Fixture::new();
    fixture.adopt(&fixture.release(1));
    fixture.host.fail_health_for.set(Some(2));
    assert!(matches!(
        fixture.update(&fixture.release(2)),
        Err(ReleaseError::ServerUpdateRolledBack)
    ));
    assert_eq!(fixture.installed(), 1);
    assert_eq!(
        fixture
            .store
            .inspect()
            .unwrap()
            .unwrap()
            .highest_accepted_release_sequence,
        1
    );
    assert!(
        !fixture
            .store
            .inspect_server_release()
            .unwrap()
            .recovery_pending
    );
}

#[test]
fn interrupted_update_recovers_before_services_start_at_every_host_boundary() {
    // Preflight, stop, both final readers, replace, start, health. A cut after
    // replacement leaves the candidate bytes in place with the previous receipt.
    for cut in 1..=8 {
        let fixture = Fixture::new();
        fixture.adopt(&fixture.release(1));
        let candidate = fixture.release(2);
        fixture.host.cut_at.set(Some(cut));
        let interrupted =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| fixture.update(&candidate)));
        assert!(interrupted.is_err(), "cut {cut} did not interrupt");
        fixture.host.cut_at.set(None);
        fixture.host.calls.borrow_mut().clear();
        fixture.store.recover_server(&fixture.host, false).unwrap();
        assert_eq!(
            fixture.installed(),
            if cut == 8 { 2 } else { 1 },
            "cut {cut}"
        );
        assert!(
            !fixture
                .host
                .calls
                .borrow()
                .iter()
                .any(|call| call == "start" || call == "stop")
        );
        assert!(
            !fixture
                .store
                .inspect_server_release()
                .unwrap()
                .recovery_pending
        );
    }
}

#[test]
fn committed_receipt_with_pending_journal_finalizes_candidate() {
    let fixture = Fixture::new();
    fixture.adopt(&fixture.release(1));
    let previous = fixture.store.read_receipt_unlocked().unwrap().unwrap();
    fixture.update(&fixture.release(2)).unwrap();
    let candidate = fixture.store.read_receipt_unlocked().unwrap().unwrap();
    fixture
        .store
        .write_server_journal(&ServerUpdateJournal {
            schema_version: 1,
            previous,
            candidate,
        })
        .unwrap();
    assert_eq!(
        fixture.store.recover_server(&fixture.host, false).unwrap(),
        ServerRecoveryAction::FinalizedCandidateRelease
    );
    assert_eq!(fixture.installed(), 2);
}

#[test]
fn rollback_revalidates_current_state_and_never_restores_an_old_authorization_copy() {
    let fixture = Fixture::new();
    fixture.adopt(&fixture.release(1));
    fixture.update(&fixture.release(2)).unwrap();
    fixture.host.calls.borrow_mut().clear();
    fixture.host.schema.set(2);
    assert!(
        fixture
            .store
            .rollback_server_with_root(&fixture.host, &fixture.root_public)
            .is_err()
    );
    assert_eq!(fixture.installed(), 2);
    assert_eq!(fixture.host.schema.get(), 2);
    assert!(
        !fixture
            .host
            .calls
            .borrow()
            .iter()
            .any(|call| call == "stop" || call == "replace")
    );
}

#[test]
fn handoff_guard_and_bidirectional_schema_support_are_mandatory() {
    for missing in ["server_handoff_guard", "server_maintenance_guard"] {
        let fixture = Fixture::new();
        fixture.adopt(&fixture.release(1));
        let mut candidate = fixture.release(2);
        let mut manifest = crate::parse_manifest(&candidate.manifest).unwrap();
        manifest
            .state_compatibility
            .retain(|state| state.state != missing);
        candidate.manifest = encode_manifest(&manifest).unwrap();
        candidate.signature = sign_manifest(&candidate.manifest, &fixture.signing).unwrap();
        assert!(matches!(
            fixture.update(&candidate),
            Err(ReleaseError::ServerUpdateUnsupported)
        ));
        assert_eq!(fixture.installed(), 1);
        assert!(fixture.host.calls.borrow().is_empty());
    }
}

#[test]
fn tampered_recovery_cache_cannot_execute_and_keeps_pending_journal() {
    use std::os::unix::fs::PermissionsExt;
    let fixture = Fixture::new();
    fixture.adopt(&fixture.release(1));
    fixture.host.cut_at.set(Some(5));
    let candidate = fixture.release(2);
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| fixture.update(&candidate)));
    fixture.host.cut_at.set(None);
    fixture.host.calls.borrow_mut().clear();
    let journal = fixture.store.read_server_journal().unwrap().unwrap();
    let cache = fixture
        .store
        .cached_artifact_path(&journal.previous.active_artifact)
        .unwrap();
    fs::set_permissions(&cache, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(cache, b"tampered").unwrap();
    assert!(fixture.store.recover_server(&fixture.host, false).is_err());
    assert!(fixture.host.calls.borrow().is_empty());
    assert!(
        fixture
            .store
            .state_directory()
            .join("server-transaction.json")
            .exists()
    );
}

#[test]
fn unrelated_client_migrations_do_not_block_vps_updates_or_rollback() {
    let fixture = Fixture::new();
    fixture.adopt(&fixture.release(1));
    let mut candidate = fixture.release(2);
    let mut manifest = crate::parse_manifest(&candidate.manifest).unwrap();
    for state in ["android_new_state", "windows_new_state"] {
        manifest.state_compatibility.push(StateCompatibility {
            state: state.to_owned(),
            reads: SchemaRange {
                minimum: 7,
                maximum: 7,
            },
            writes: SchemaRange {
                minimum: 7,
                maximum: 7,
            },
        });
    }
    manifest
        .state_compatibility
        .sort_by(|a, b| a.state.cmp(&b.state));
    candidate.manifest = encode_manifest(&manifest).unwrap();
    candidate.signature = sign_manifest(&candidate.manifest, &fixture.signing).unwrap();
    fixture.update(&candidate).unwrap();
    fixture
        .store
        .rollback_server_with_root(&fixture.host, &fixture.root_public)
        .unwrap();
    assert_eq!(fixture.installed(), 1);
}

#[test]
fn a_migration_that_the_previous_server_cannot_read_never_stops_the_service() {
    let fixture = Fixture::new();
    fixture.adopt(&fixture.release(1));
    let mut candidate = fixture.release(2);
    let mut manifest = crate::parse_manifest(&candidate.manifest).unwrap();
    let state = manifest
        .state_compatibility
        .iter_mut()
        .find(|state| state.state == "server_authorization")
        .unwrap();
    state.reads.maximum = 2;
    state.writes.maximum = 2;
    candidate.manifest = encode_manifest(&manifest).unwrap();
    candidate.signature = sign_manifest(&candidate.manifest, &fixture.signing).unwrap();
    assert!(matches!(
        fixture.update(&candidate),
        Err(ReleaseError::RollbackIncompatible(_))
    ));
    assert!(fixture.host.calls.borrow().is_empty());
    assert_eq!(fixture.installed(), 1);
}

#[test]
fn key_revocation_blocks_explicit_rollback_but_keeps_failed_update_recovery_possible() {
    let fixture = Fixture::new();
    fixture.adopt(&fixture.release(1));
    let revoked = fixture.store.inspect().unwrap().unwrap().key_id_sha256;
    let (new_private, new_public) = generate_signing_keypair().unwrap();
    let policy =
        encode_trust_policy(&build_trust_policy(2, vec![new_public], vec![revoked]).unwrap())
            .unwrap();
    let signature = sign_trust_policy(&policy, &fixture.root_private).unwrap();
    fixture
        .store
        .apply_trust_policy_with_root(&policy, &signature, &fixture.root_public)
        .unwrap();
    let mut candidate = fixture.release(2);
    candidate.signature = sign_manifest(&candidate.manifest, &new_private).unwrap();
    fixture.host.fail_health_for.set(Some(2));
    assert!(matches!(
        fixture.update(&candidate),
        Err(ReleaseError::ServerUpdateRolledBack)
    ));
    assert_eq!(fixture.installed(), 1);
    fixture.host.fail_health_for.set(None);
    fixture.update(&candidate).unwrap();
    assert!(matches!(
        fixture
            .store
            .rollback_server_with_root(&fixture.host, &fixture.root_public),
        Err(ReleaseError::ReleaseKeyRevoked)
    ));
    assert_eq!(fixture.installed(), 2);
}
