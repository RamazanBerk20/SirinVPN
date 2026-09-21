use super::*;

#[test]
fn successful_update_commits_receipt_only_after_candidate_health() {
    let root = tempfile::tempdir().unwrap();
    let store = InstalledReleaseStore::new(root.path().join("state"));
    let keys = keys();
    let current = release(root.path(), &keys, "0.1.0", 1);
    let candidate = release(root.path(), &keys, "0.2.0", 2);
    initialize(&store, &current, &keys.public);
    let manager = FakePackageManager::installed("0.1.0");
    manager.observe_receipt(store.receipt_path());

    let installed = install(&store, &candidate, &keys.public, &manager).unwrap();

    assert_eq!(installed.action, InstallationDecisionKind::Upgrade);
    assert_eq!(installed.state.active_release_version, "0.2.0");
    assert_eq!(manager.installed_version.borrow().as_str(), "0.2.0");
    assert_eq!(
        manager.events(),
        [
            "lock-network",
            "preflight:0.1.0",
            "health:0.1.0",
            "preflight:0.2.0",
            "install:0.2.0",
            "health:0.2.0"
        ]
    );
    assert!(
        manager
            .observed_health_receipts
            .borrow()
            .contains(&("0.2.0".to_owned(), "0.1.0".to_owned()))
    );
    assert!(!store.journal_path().exists());
    assert_eq!(
        cached_files(&store),
        [format!("{}.deb", candidate.artifact.sha256)]
    );
}

#[test]
fn trusted_debian_update_rotates_to_a_root_authorized_release_key() {
    let root = tempfile::tempdir().unwrap();
    let store = InstalledReleaseStore::new(root.path().join("state"));
    let trust_root = keys();
    let old_keys = keys();
    let new_keys = keys();
    let current = release(root.path(), &old_keys, "0.1.0", 1);
    let candidate = release(root.path(), &new_keys, "0.2.0", 2);

    apply_trust(&store, &trust_root, 1, &[&old_keys]);
    store
        .commit_trusted_installation_with_root(
            &current.manifest,
            &current.signature,
            &current.directory,
            ArtifactKind::LinuxDeb,
            TARGET,
            false,
            &trust_root.public,
        )
        .unwrap();
    apply_trust(&store, &trust_root, 2, &[&old_keys, &new_keys]);

    let manager = FakePackageManager::installed("0.1.0");
    let installed = store
        .install_trusted_debian_with_root(
            &candidate.manifest,
            &candidate.signature,
            &candidate.directory,
            TARGET,
            false,
            &trust_root.public,
            &manager,
        )
        .unwrap();
    assert_eq!(installed.action, InstallationDecisionKind::Upgrade);
    assert_eq!(manager.installed_version.borrow().as_str(), "0.2.0");
    assert_eq!(
        installed.state.key_id_sha256,
        public_key_id(&new_keys.public).unwrap()
    );
    assert!(matches!(
        install(&store, &candidate, &new_keys.public, &manager),
        Err(ReleaseError::InstalledTrustForbidsExplicitKey)
    ));
}

#[test]
fn failed_candidate_install_restores_previous_package_and_receipt() {
    let root = tempfile::tempdir().unwrap();
    let store = InstalledReleaseStore::new(root.path().join("state"));
    let keys = keys();
    let current = release(root.path(), &keys, "0.1.0", 1);
    let candidate = release(root.path(), &keys, "0.2.0", 2);
    initialize(&store, &current, &keys.public);
    let receipt_before = fs::read(store.receipt_path()).unwrap();
    let manager = FakePackageManager::installed("0.1.0");
    manager.fail_next_install("0.2.0");

    assert!(matches!(
        install(&store, &candidate, &keys.public, &manager),
        Err(ReleaseError::DebianUpdateRolledBack)
    ));
    assert_eq!(fs::read(store.receipt_path()).unwrap(), receipt_before);
    assert_eq!(manager.installed_version.borrow().as_str(), "0.1.0");
    assert_eq!(
        manager.events(),
        [
            "lock-network",
            "preflight:0.1.0",
            "health:0.1.0",
            "preflight:0.2.0",
            "install:0.2.0",
            "preflight:0.1.0",
            "install:0.1.0",
            "health:0.1.0"
        ]
    );
    assert!(!store.journal_path().exists());
    assert_eq!(
        cached_files(&store),
        [format!("{}.deb", current.artifact.sha256)]
    );
}

#[test]
fn failed_candidate_health_restores_previous_package() {
    let root = tempfile::tempdir().unwrap();
    let store = InstalledReleaseStore::new(root.path().join("state"));
    let keys = keys();
    let current = release(root.path(), &keys, "0.1.0", 1);
    let candidate = release(root.path(), &keys, "0.2.0", 2);
    initialize(&store, &current, &keys.public);
    let manager = FakePackageManager::installed("0.1.0");
    manager.fail_next_health("0.2.0");

    assert!(matches!(
        install(&store, &candidate, &keys.public, &manager),
        Err(ReleaseError::DebianUpdateRolledBack)
    ));
    assert_eq!(manager.installed_version.borrow().as_str(), "0.1.0");
    assert_eq!(
        manager.events(),
        [
            "lock-network",
            "preflight:0.1.0",
            "health:0.1.0",
            "preflight:0.2.0",
            "install:0.2.0",
            "health:0.2.0",
            "preflight:0.1.0",
            "install:0.1.0",
            "health:0.1.0"
        ]
    );
    assert_eq!(
        store.inspect().unwrap().unwrap().active_release_version,
        "0.1.0"
    );
}

#[test]
fn failed_rollback_retains_journal_and_recovers_idempotently() {
    let root = tempfile::tempdir().unwrap();
    let store = InstalledReleaseStore::new(root.path().join("state"));
    let keys = keys();
    let current = release(root.path(), &keys, "0.1.0", 1);
    let candidate = release(root.path(), &keys, "0.2.0", 2);
    initialize(&store, &current, &keys.public);
    let manager = FakePackageManager::installed("0.1.0");
    manager.fail_next_health("0.2.0");
    manager.fail_next_install("0.1.0");

    assert!(matches!(
        install(&store, &candidate, &keys.public, &manager),
        Err(ReleaseError::DebianUpdateRecoveryRequired)
    ));
    assert!(store.journal_path().exists());
    assert_eq!(cached_files(&store).len(), 2);
    assert_eq!(
        store.inspect().unwrap().unwrap().active_release_version,
        "0.1.0"
    );

    let recovered = store.recover_debian_with(&manager).unwrap();
    assert_eq!(
        recovered.action,
        DebianRecoveryAction::RestoredPreviousRelease
    );
    assert_eq!(manager.installed_version.borrow().as_str(), "0.1.0");
    assert!(!store.journal_path().exists());
    assert_eq!(cached_files(&store).len(), 1);

    let retry = store.recover_debian_with(&manager).unwrap();
    assert_eq!(retry.action, DebianRecoveryAction::NothingPending);
}

#[test]
fn recovery_finalizes_a_candidate_whose_receipt_was_already_committed() {
    let root = tempfile::tempdir().unwrap();
    let store = InstalledReleaseStore::new(root.path().join("state"));
    let keys = keys();
    let current = release(root.path(), &keys, "0.1.0", 1);
    let candidate_release = release(root.path(), &keys, "0.2.0", 2);
    initialize(&store, &current, &keys.public);

    let (candidate, canonical_key) = crate::installed_release::verify_candidate(
        &candidate_release.manifest,
        &candidate_release.signature,
        &keys.public,
        &candidate_release.directory,
        ArtifactKind::LinuxDeb,
        TARGET,
    )
    .unwrap();
    let lock = store.open_lock().unwrap();
    FileExt::lock_exclusive(&lock).unwrap();
    let previous = store.read_receipt_unlocked().unwrap().unwrap();
    let (proposed, _) =
        crate::installed_release::evaluate(Some(previous.clone()), candidate, canonical_key, false)
            .unwrap();
    store
        .cache_artifact_unlocked(&candidate_release.directory, &proposed.active_artifact)
        .unwrap();
    store
        .write_journal_unlocked(&DebianUpdateJournal::new(&previous, &proposed))
        .unwrap();
    store.write_receipt_unlocked(&proposed).unwrap();
    FileExt::unlock(&lock).unwrap();

    let manager = FakePackageManager::installed("0.2.0");
    let recovered = store.recover_debian_with(&manager).unwrap();
    assert_eq!(
        recovered.action,
        DebianRecoveryAction::FinalizedCandidateRelease
    );
    assert_eq!(
        manager.events(),
        ["lock-network", "preflight:0.2.0", "health:0.2.0"]
    );
    assert_eq!(recovered.state.active_release_version, "0.2.0");
    assert!(!store.journal_path().exists());
    assert_eq!(cached_files(&store).len(), 1);
}

#[test]
fn identical_candidate_is_a_verified_noop() {
    let root = tempfile::tempdir().unwrap();
    let store = InstalledReleaseStore::new(root.path().join("state"));
    let keys = keys();
    let current = release(root.path(), &keys, "0.1.0", 1);
    initialize(&store, &current, &keys.public);
    let manager = FakePackageManager::installed("0.1.0");

    let result = install(&store, &current, &keys.public, &manager).unwrap();
    assert_eq!(result.action, InstallationDecisionKind::AlreadyBound);
    assert_eq!(
        manager.events(),
        ["lock-network", "preflight:0.1.0", "health:0.1.0"]
    );
    assert!(!store.journal_path().exists());
}

#[test]
fn explicit_package_rollback_retains_the_signed_high_watermark() {
    let root = tempfile::tempdir().unwrap();
    let store = InstalledReleaseStore::new(root.path().join("state"));
    let keys = keys();
    let first = release(root.path(), &keys, "0.1.0", 1);
    let middle = release(root.path(), &keys, "0.2.0", 2);
    let latest = release(root.path(), &keys, "0.3.0", 3);
    initialize(&store, &first, &keys.public);
    let manager = FakePackageManager::installed("0.1.0");
    install(&store, &latest, &keys.public, &manager).unwrap();

    let rollback = install_allowing_rollback(&store, &first, &keys.public, true, &manager).unwrap();
    assert_eq!(rollback.action, InstallationDecisionKind::Rollback);
    assert_eq!(rollback.state.active_release_sequence, 1);
    assert_eq!(rollback.state.highest_accepted_release_sequence, 3);
    assert_eq!(manager.installed_version.borrow().as_str(), "0.1.0");
    assert_eq!(
        cached_files(&store),
        [format!("{}.deb", first.artifact.sha256)]
    );

    assert!(matches!(
        install(&store, &middle, &keys.public, &manager),
        Err(ReleaseError::BelowHighestAcceptedRelease)
    ));
    let restored = install(&store, &latest, &keys.public, &manager).unwrap();
    assert_eq!(restored.action, InstallationDecisionKind::Upgrade);
    assert_eq!(restored.state.active_release_sequence, 3);
    assert_eq!(restored.state.highest_accepted_release_sequence, 3);
    assert_eq!(manager.installed_version.borrow().as_str(), "0.3.0");
}

#[test]
fn updater_requires_receipt_transaction_support_and_intact_cache() {
    let root = tempfile::tempdir().unwrap();
    let store = InstalledReleaseStore::new(root.path().join("state"));
    let keys = keys();
    let current = release(root.path(), &keys, "0.1.0", 1);
    let candidate = release(root.path(), &keys, "0.2.0", 2);
    let manager = FakePackageManager::installed("0.1.0");

    assert!(matches!(
        install(&store, &candidate, &keys.public, &manager),
        Err(ReleaseError::DebianUpdateReceiptRequired)
    ));
    assert!(!store.receipt_path().exists());

    let receipt_only = vec![StateCompatibility {
        state: "linux_release_receipt".to_owned(),
        reads: SchemaRange {
            minimum: 1,
            maximum: 1,
        },
        writes: SchemaRange {
            minimum: 1,
            maximum: 1,
        },
    }];
    let legacy_store = InstalledReleaseStore::new(root.path().join("legacy-state"));
    let legacy_current =
        release_with_compatibility(root.path(), &keys, "1.0.0", 10, receipt_only.clone());
    let legacy_candidate =
        release_with_compatibility(root.path(), &keys, "1.1.0", 11, receipt_only);
    initialize(&legacy_store, &legacy_current, &keys.public);
    let legacy_manager = FakePackageManager::installed("1.0.0");
    assert!(matches!(
        install(
            &legacy_store,
            &legacy_candidate,
            &keys.public,
            &legacy_manager
        ),
        Err(ReleaseError::DebianUpdateStateUnsupported)
    ));
    assert_eq!(legacy_manager.events(), ["lock-network"]);

    initialize(&store, &current, &keys.public);
    let current_receipt = store.read_receipt_unlocked().unwrap().unwrap();
    let cached = store
        .cached_artifact_path(&current_receipt.active_artifact)
        .unwrap();
    fs::write(cached, "tampered").unwrap();
    assert!(matches!(
        store.inspect(),
        Err(ReleaseError::InvalidInstalledPackageCache)
    ));

    let parsed = parse_manifest(&candidate.manifest).unwrap();
    assert!(
        parsed
            .state_compatibility
            .iter()
            .any(|state| state.state == TRANSACTION_STATE_NAME)
    );
}

#[test]
fn noncanonical_journal_fails_before_package_operations() {
    let root = tempfile::tempdir().unwrap();
    let store = InstalledReleaseStore::new(root.path().join("state"));
    let keys = keys();
    let current = release(root.path(), &keys, "0.1.0", 1);
    let candidate_release = release(root.path(), &keys, "0.2.0", 2);
    initialize(&store, &current, &keys.public);
    let (candidate, canonical_key) = crate::installed_release::verify_candidate(
        &candidate_release.manifest,
        &candidate_release.signature,
        &keys.public,
        &candidate_release.directory,
        ArtifactKind::LinuxDeb,
        TARGET,
    )
    .unwrap();
    let previous = store.read_receipt_unlocked().unwrap().unwrap();
    let (proposed, _) =
        crate::installed_release::evaluate(Some(previous.clone()), candidate, canonical_key, false)
            .unwrap();
    store
        .cache_artifact_unlocked(&candidate_release.directory, &proposed.active_artifact)
        .unwrap();
    let journal = DebianUpdateJournal::new(&previous, &proposed);
    fs::write(
        store.journal_path(),
        serde_json::to_vec_pretty(&journal).unwrap(),
    )
    .unwrap();
    fs::set_permissions(store.journal_path(), fs::Permissions::from_mode(0o600)).unwrap();
    let manager = FakePackageManager::installed("0.1.0");

    assert!(matches!(
        store.recover_debian_with(&manager),
        Err(ReleaseError::NonCanonicalDebianUpdateJournal)
    ));
    assert_eq!(manager.events(), ["lock-network"]);
}
