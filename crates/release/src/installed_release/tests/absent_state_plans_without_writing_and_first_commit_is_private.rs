use super::*;

#[test]
fn absent_state_plans_without_writing_and_first_commit_is_private() {
    let root = tempfile::tempdir().unwrap();
    let state = root.path().join("state");
    let store = InstalledReleaseStore::new(&state);
    let keys = test_keys();
    let first = release(root.path(), &keys, "0.1.0", 1, "first");

    assert!(matches!(
        store.commit_installation(
            &first.manifest,
            &first.signature,
            &keys.public,
            &first.directory,
            ArtifactKind::AndroidApk,
            TARGET,
            false,
        ),
        Err(ReleaseError::ArtifactUnavailable { .. })
    ));
    assert!(!state.exists());

    let planned = plan(&store, &first, &keys.public, false).unwrap();
    assert_eq!(planned.action, InstallationDecisionKind::Initialize);
    assert!(!state.exists());

    let committed = commit(&store, &first, &keys.public, false).unwrap();
    assert_eq!(committed.action, InstallationDecisionKind::Initialize);
    assert_eq!(committed.state.active_release_sequence, 1);
    assert_eq!(committed.state.highest_accepted_release_sequence, 1);
    #[cfg(unix)]
    {
        assert_eq!(
            fs::metadata(&state).unwrap().permissions().mode() & 0o777,
            0o700
        );
        for name in [RECEIPT_FILE_NAME, LOCK_FILE_NAME] {
            assert_eq!(
                fs::metadata(state.join(name)).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        assert_eq!(
            fs::metadata(store.package_directory())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
    }
    let cached = store
        .cached_artifact_path(&committed.state.active_artifact)
        .unwrap();
    assert_eq!(fs::read(&cached).unwrap(), b"first");
    #[cfg(unix)]
    assert_eq!(
        fs::metadata(cached).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(store.inspect().unwrap(), Some(committed.state));
}

#[test]
fn root_authorized_release_key_rotation_and_revocation_preserve_receipt_compatibility() {
    let root = tempfile::tempdir().unwrap();
    let store = InstalledReleaseStore::new(root.path().join("state"));
    let trust_root = test_keys();
    let old_keys = test_keys();
    let new_keys = test_keys();
    let first = release(root.path(), &old_keys, "0.1.0", 1, "old");
    let successor = release(root.path(), &new_keys, "0.2.0", 2, "new");
    let compromised = release(root.path(), &old_keys, "0.3.0", 3, "revoked");

    assert!(matches!(
        store.commit_trusted_installation_with_root(
            &first.manifest,
            &first.signature,
            &first.directory,
            ArtifactKind::LinuxAppImage,
            TARGET,
            false,
            &trust_root.public,
        ),
        Err(ReleaseError::InstalledTrustRequired)
    ));

    apply_trust(&store, &trust_root, 1, &[&old_keys], vec![]);
    let initialized = store
        .commit_trusted_installation_with_root(
            &first.manifest,
            &first.signature,
            &first.directory,
            ArtifactKind::LinuxAppImage,
            TARGET,
            false,
            &trust_root.public,
        )
        .unwrap();
    assert_eq!(initialized.action, InstallationDecisionKind::Initialize);
    assert!(matches!(
        plan(&store, &first, &old_keys.public, false),
        Err(ReleaseError::InstalledTrustForbidsExplicitKey)
    ));

    apply_trust(&store, &trust_root, 2, &[&old_keys, &new_keys], vec![]);
    let upgraded = store
        .commit_trusted_installation_with_root(
            &successor.manifest,
            &successor.signature,
            &successor.directory,
            ArtifactKind::LinuxAppImage,
            TARGET,
            false,
            &trust_root.public,
        )
        .unwrap();
    assert_eq!(upgraded.action, InstallationDecisionKind::Upgrade);
    assert_eq!(
        upgraded.state.key_id_sha256,
        public_key_id(&new_keys.public).unwrap()
    );
    assert_eq!(store.inspect().unwrap(), Some(upgraded.state.clone()));
    assert!(matches!(
        store.plan_trusted_installation_with_root(
            &first.manifest,
            &first.signature,
            &first.directory,
            ArtifactKind::LinuxAppImage,
            TARGET,
            true,
            &trust_root.public,
        ),
        Err(ReleaseError::ReleaseKeyTransitionRequiresUpgrade)
    ));

    let receipt_before_revocation = fs::read(store.receipt_path()).unwrap();
    let old_id = public_key_id(&old_keys.public).unwrap();
    apply_trust(&store, &trust_root, 3, &[&new_keys], vec![old_id]);
    assert_eq!(
        fs::read(store.receipt_path()).unwrap(),
        receipt_before_revocation
    );
    assert!(matches!(
        store.plan_trusted_installation_with_root(
            &compromised.manifest,
            &compromised.signature,
            &compromised.directory,
            ArtifactKind::LinuxAppImage,
            TARGET,
            false,
            &trust_root.public,
        ),
        Err(ReleaseError::ReleaseKeyRevoked)
    ));
    assert_eq!(
        store
            .plan_trusted_installation_with_root(
                &successor.manifest,
                &successor.signature,
                &successor.directory,
                ArtifactKind::LinuxAppImage,
                TARGET,
                false,
                &trust_root.public,
            )
            .unwrap()
            .action,
        InstallationDecisionKind::AlreadyBound
    );
}

#[test]
fn existing_receipt_adoption_requires_compatibility_and_its_current_key() {
    let root = tempfile::tempdir().unwrap();
    let trust_root = test_keys();
    let current_keys = test_keys();
    let unrelated_keys = test_keys();
    let store = InstalledReleaseStore::new(root.path().join("compatible-state"));
    let current = release(root.path(), &current_keys, "1.0.0", 10, "compatible");
    commit(&store, &current, &current_keys.public, false).unwrap();

    let wrong_policy = build_trust_policy(1, vec![unrelated_keys.public.clone()], vec![])
        .and_then(|policy| encode_trust_policy(&policy))
        .unwrap();
    let wrong_signature = sign_trust_policy(&wrong_policy, &trust_root.private).unwrap();
    assert!(matches!(
        store.apply_trust_policy_with_root(&wrong_policy, &wrong_signature, &trust_root.public),
        Err(ReleaseError::InstalledTrustDoesNotAuthorizeCurrentKey)
    ));
    assert!(!store.trust_path().exists());
    apply_trust(&store, &trust_root, 1, &[&current_keys], vec![]);

    let legacy_store = InstalledReleaseStore::new(root.path().join("legacy-state"));
    let legacy = release_with_compatibility(
        root.path(),
        &current_keys,
        "2.0.0",
        20,
        "legacy",
        vec![StateCompatibility {
            state: "linux_release_receipt".to_owned(),
            reads: SchemaRange {
                minimum: 1,
                maximum: 1,
            },
            writes: SchemaRange {
                minimum: 1,
                maximum: 1,
            },
        }],
    );
    commit(&legacy_store, &legacy, &current_keys.public, false).unwrap();
    let policy = build_trust_policy(1, vec![current_keys.public.clone()], vec![])
        .and_then(|policy| encode_trust_policy(&policy))
        .unwrap();
    let signature = sign_trust_policy(&policy, &trust_root.private).unwrap();
    assert!(matches!(
        legacy_store.apply_trust_policy_with_root(&policy, &signature, &trust_root.public),
        Err(ReleaseError::InstalledTrustAdoptionUnsupported)
    ));
    assert!(!legacy_store.trust_path().exists());
}

#[test]
fn first_commit_rejects_a_release_that_cannot_preserve_the_receipt() {
    let root = tempfile::tempdir().unwrap();
    let directory = root.path().join("legacy-release");
    fs::create_dir(&directory).unwrap();
    let artifact_path = directory.join("SirinVPN.AppImage");
    fs::write(&artifact_path, "legacy").unwrap();
    let keys = test_keys();
    let artifact =
        ReleaseArtifact::from_path(ArtifactKind::LinuxAppImage, TARGET, &artifact_path).unwrap();
    let manifest = build_manifest(
        "0.1.0",
        1,
        ReleaseChannel::Stable,
        false,
        vec![artifact],
        vec![StateCompatibility {
            state: "linux_client_profiles".to_owned(),
            reads: SchemaRange {
                minimum: 1,
                maximum: 1,
            },
            writes: SchemaRange {
                minimum: 1,
                maximum: 1,
            },
        }],
    )
    .unwrap();
    let manifest = encode_manifest(&manifest).unwrap();
    let signature = sign_manifest(&manifest, &keys.private).unwrap();
    let store = InstalledReleaseStore::new(root.path().join("state"));

    assert!(matches!(
        store.commit_installation(
            &manifest,
            &signature,
            &keys.public,
            &directory,
            ArtifactKind::LinuxAppImage,
            TARGET,
            false,
        ),
        Err(ReleaseError::InstalledReceiptUnsupported)
    ));
    assert!(!root.path().join("state").exists());
}

#[test]
fn upgrade_rollback_and_highest_release_recovery_are_monotonic() {
    let root = tempfile::tempdir().unwrap();
    let store = InstalledReleaseStore::new(root.path().join("state"));
    let keys = test_keys();
    let first = release(root.path(), &keys, "0.1.0", 1, "first");
    let middle = release(root.path(), &keys, "0.2.0", 2, "middle");
    let latest = release(root.path(), &keys, "0.3.0", 3, "latest");

    commit(&store, &first, &keys.public, false).unwrap();
    let before_plan = fs::read(store.receipt_path()).unwrap();
    assert_eq!(
        plan(&store, &latest, &keys.public, false).unwrap().action,
        InstallationDecisionKind::Upgrade
    );
    assert_eq!(fs::read(store.receipt_path()).unwrap(), before_plan);
    commit(&store, &latest, &keys.public, false).unwrap();

    let before_refused_rollback = fs::read(store.receipt_path()).unwrap();
    assert!(matches!(
        commit(&store, &first, &keys.public, false),
        Err(ReleaseError::RollbackConfirmationRequired)
    ));
    assert_eq!(
        fs::read(store.receipt_path()).unwrap(),
        before_refused_rollback
    );

    let rolled_back = commit(&store, &first, &keys.public, true).unwrap();
    assert_eq!(rolled_back.action, InstallationDecisionKind::Rollback);
    assert_eq!(rolled_back.state.active_release_sequence, 1);
    assert_eq!(rolled_back.state.highest_accepted_release_sequence, 3);
    assert!(matches!(
        commit(&store, &middle, &keys.public, false),
        Err(ReleaseError::BelowHighestAcceptedRelease)
    ));

    let recovered = commit(&store, &latest, &keys.public, false).unwrap();
    assert_eq!(recovered.action, InstallationDecisionKind::Upgrade);
    assert_eq!(recovered.state.active_release_sequence, 3);
    assert_eq!(recovered.state.highest_accepted_release_sequence, 3);
    let before_retry = fs::read(store.receipt_path()).unwrap();
    assert_eq!(
        commit(&store, &latest, &keys.public, false).unwrap().action,
        InstallationDecisionKind::AlreadyBound
    );
    assert_eq!(fs::read(store.receipt_path()).unwrap(), before_retry);
}

#[test]
fn key_change_sequence_reuse_and_changed_artifact_preserve_receipt() {
    let root = tempfile::tempdir().unwrap();
    let store = InstalledReleaseStore::new(root.path().join("state"));
    let keys = test_keys();
    let first = release(root.path(), &keys, "0.1.0", 1, "first");
    let second = release(root.path(), &keys, "0.2.0", 2, "second");
    commit(&store, &first, &keys.public, false).unwrap();
    let original = fs::read(store.receipt_path()).unwrap();

    let wrong_keys = test_keys();
    let wrong_release = release(root.path(), &wrong_keys, "0.2.0", 2, "wrong-key");
    assert!(matches!(
        commit(&store, &wrong_release, &wrong_keys.public, false),
        Err(ReleaseError::KeyIdMismatch)
    ));
    assert_eq!(fs::read(store.receipt_path()).unwrap(), original);

    let collision = release(root.path(), &keys, "0.1.1", 1, "collision");
    assert!(matches!(
        commit(&store, &collision, &keys.public, false),
        Err(ReleaseError::ReleaseSequenceCollision)
    ));
    assert_eq!(fs::read(store.receipt_path()).unwrap(), original);

    let parsed = crate::parse_manifest(&second.manifest).unwrap();
    fs::write(
        second.directory.join(&parsed.artifacts[0].file_name),
        "modified",
    )
    .unwrap();
    assert!(matches!(
        commit(&store, &second, &keys.public, false),
        Err(ReleaseError::ArtifactDigestMismatch(_)) | Err(ReleaseError::ArtifactSizeMismatch(_))
    ));
    assert_eq!(fs::read(store.receipt_path()).unwrap(), original);
}

#[test]
fn receipt_tampering_noncanonical_data_and_unsafe_paths_fail_closed() {
    let root = tempfile::tempdir().unwrap();
    let state = root.path().join("state");
    let store = InstalledReleaseStore::new(&state);
    let keys = test_keys();
    let first = release(root.path(), &keys, "0.1.0", 1, "first");
    commit(&store, &first, &keys.public, false).unwrap();
    let receipt_path = store.receipt_path();
    let canonical = fs::read(&receipt_path).unwrap();

    let receipt: InstalledReleaseReceipt = serde_json::from_slice(&canonical).unwrap();
    fs::write(&receipt_path, serde_json::to_vec(&receipt).unwrap()).unwrap();
    assert!(matches!(
        store.inspect(),
        Err(ReleaseError::NonCanonicalInstalledReceipt)
    ));

    let mut future = receipt.clone();
    future.schema_version = 2;
    fs::write(&receipt_path, canonical_json(&future).unwrap()).unwrap();
    assert!(matches!(
        store.inspect(),
        Err(ReleaseError::InvalidInstalledReceipt)
    ));

    fs::write(&receipt_path, &canonical).unwrap();
    let mut value: serde_json::Value = serde_json::from_slice(&canonical).unwrap();
    value["unexpected"] = serde_json::json!(true);
    fs::write(&receipt_path, canonical_json(&value).unwrap()).unwrap();
    assert!(matches!(
        store.inspect(),
        Err(ReleaseError::InvalidInstalledReceipt)
    ));

    #[cfg(unix)]
    {
        fs::write(&receipt_path, &canonical).unwrap();
        fs::set_permissions(&receipt_path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(
            store.inspect(),
            Err(ReleaseError::UnsafeInstalledState)
        ));

        fs::remove_file(&receipt_path).unwrap();
        let external = root.path().join("external");
        fs::write(&external, &canonical).unwrap();
        fs::set_permissions(&external, fs::Permissions::from_mode(0o600)).unwrap();
        symlink(&external, &receipt_path).unwrap();
        assert!(matches!(
            store.inspect(),
            Err(ReleaseError::UnsafeInstalledState)
        ));

        fs::remove_file(&receipt_path).unwrap();
        fs::hard_link(&external, &receipt_path).unwrap();
        assert!(matches!(
            store.inspect(),
            Err(ReleaseError::UnsafeInstalledState)
        ));
    }
}

#[cfg(unix)]
#[test]
fn state_directory_and_lock_must_be_private_regular_owned_paths() {
    let root = tempfile::tempdir().unwrap();
    let state = root.path().join("state");
    fs::create_dir(&state).unwrap();
    fs::set_permissions(&state, fs::Permissions::from_mode(0o755)).unwrap();
    let store = InstalledReleaseStore::new(&state);
    assert!(matches!(
        store.inspect(),
        Err(ReleaseError::UnsafeInstalledState)
    ));

    fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
    let external = root.path().join("external-lock");
    fs::write(&external, "lock").unwrap();
    fs::set_permissions(&external, fs::Permissions::from_mode(0o600)).unwrap();
    symlink(&external, state.join(LOCK_FILE_NAME)).unwrap();
    assert!(matches!(
        store.inspect(),
        Err(ReleaseError::UnsafeInstalledState)
    ));
}
