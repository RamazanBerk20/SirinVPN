use super::*;

#[test]
fn signed_release_verifies_every_artifact() {
    let directory = tempfile::tempdir().unwrap();
    let (manifest, signature, public) =
        signed_release(directory.path(), "0.2.0", 2, compatibility());
    let verified =
        verify_release_directory(&manifest, &signature, &public, directory.path()).unwrap();
    assert_eq!(verified.manifest.release_version, "0.2.0");
    assert_eq!(verified.verified_artifacts, 1);
    assert_eq!(verified.key_id_sha256, public_key_id(&public).unwrap());
    assert_eq!(
        verified
            .artifact(ArtifactKind::LinuxAppImage, "x86_64-unknown-linux-gnu")
            .unwrap()
            .file_name,
        "sirinvpn-2.AppImage"
    );
    assert!(matches!(
        verified.artifact(ArtifactKind::LinuxDeb, "x86_64-unknown-linux-gnu"),
        Err(ReleaseError::ArtifactUnavailable { .. })
    ));
}

#[test]
fn tampering_wrong_keys_and_noncanonical_json_fail_closed() {
    let directory = tempfile::tempdir().unwrap();
    let (manifest, signature, public) =
        signed_release(directory.path(), "0.2.0", 2, compatibility());
    let mut tampered = manifest.clone();
    let position = tampered
        .windows(b"0.2.0".len())
        .position(|window| window == b"0.2.0")
        .unwrap();
    tampered[position + 2] = b'3';
    assert!(matches!(
        verify_manifest(&tampered, &signature, &public),
        Err(ReleaseError::ManifestDigestMismatch)
    ));

    let (_, wrong_public) = generate_signing_keypair().unwrap();
    assert!(matches!(
        verify_manifest(&manifest, &signature, &wrong_public),
        Err(ReleaseError::KeyIdMismatch)
    ));

    let mut invalid_signature: ReleaseSignature = serde_json::from_slice(&signature).unwrap();
    let mut signature_bytes = STANDARD.decode(&invalid_signature.signature).unwrap();
    signature_bytes[0] ^= 1;
    invalid_signature.signature = STANDARD.encode(signature_bytes);
    let invalid_signature = canonical_json(&invalid_signature).unwrap();
    assert!(matches!(
        verify_manifest(&manifest, &invalid_signature, &public),
        Err(ReleaseError::InvalidSignature)
    ));

    let compact = serde_json::to_vec(&parse_manifest(&manifest).unwrap()).unwrap();
    assert!(matches!(
        verify_manifest(&compact, &signature, &public),
        Err(ReleaseError::NonCanonicalManifest)
    ));
}

#[test]
fn artifact_changes_and_symlinks_are_rejected() {
    let directory = tempfile::tempdir().unwrap();
    let (manifest, signature, public) =
        signed_release(directory.path(), "0.2.0", 2, compatibility());
    let parsed = parse_manifest(&manifest).unwrap();
    let artifact = directory.path().join(&parsed.artifacts[0].file_name);
    fs::write(&artifact, b"modified!!").unwrap();
    assert!(matches!(
        verify_release_directory(&manifest, &signature, &public, directory.path()),
        Err(ReleaseError::ArtifactDigestMismatch(_)) | Err(ReleaseError::ArtifactSizeMismatch(_))
    ));

    fs::remove_file(&artifact).unwrap();
    let target = directory.path().join("target");
    fs::write(&target, b"release 2").unwrap();
    symlink(&target, &artifact).unwrap();
    assert!(matches!(
        verify_release_directory(&manifest, &signature, &public, directory.path()),
        Err(ReleaseError::InvalidArtifact(_))
    ));
}

#[test]
fn valid_upgrade_is_forward_and_rollback_compatible() {
    let artifact = ReleaseArtifact {
        kind: ArtifactKind::LinuxDeb,
        target: "x86_64-unknown-linux-gnu".to_owned(),
        file_name: "sirinvpn.deb".to_owned(),
        size_bytes: 1,
        sha256: "a".repeat(64),
    };
    let current = build_manifest(
        "0.1.0",
        1,
        ReleaseChannel::Stable,
        false,
        vec![artifact.clone()],
        compatibility(),
    )
    .unwrap();
    let mut next_states = compatibility();
    next_states[0].writes.maximum = 2;
    let candidate = build_manifest(
        "0.2.0",
        2,
        ReleaseChannel::Stable,
        false,
        vec![artifact],
        next_states,
    )
    .unwrap();
    let plan = plan_transition(&current, &candidate, false).unwrap();
    assert_eq!(plan.direction, UpdateDirection::Upgrade);
    assert!(!plan.security_update);
    assert!(plan.rollback_safe);
    assert_eq!(plan.state_transitions.len(), 1);
}

#[test]
fn incompatible_forward_and_rollback_transitions_are_distinct() {
    let artifact = ReleaseArtifact {
        kind: ArtifactKind::LinuxDeb,
        target: "x86_64-unknown-linux-gnu".to_owned(),
        file_name: "sirinvpn.deb".to_owned(),
        size_bytes: 1,
        sha256: "a".repeat(64),
    };
    let current = build_manifest(
        "0.1.0",
        1,
        ReleaseChannel::Stable,
        false,
        vec![artifact.clone()],
        compatibility(),
    )
    .unwrap();

    let mut cannot_read = compatibility();
    cannot_read[0].reads.minimum = 2;
    let candidate = build_manifest(
        "0.2.0",
        2,
        ReleaseChannel::Stable,
        false,
        vec![artifact.clone()],
        cannot_read,
    )
    .unwrap();
    assert!(matches!(
        plan_transition(&current, &candidate, false),
        Err(ReleaseError::ForwardIncompatible(state)) if state == "client_profiles"
    ));

    let mut narrow_current_states = compatibility();
    narrow_current_states[0].reads.maximum = 1;
    let narrow_current = build_manifest(
        "0.1.0",
        1,
        ReleaseChannel::Stable,
        false,
        vec![artifact.clone()],
        narrow_current_states,
    )
    .unwrap();
    let mut rollback_breaking = compatibility();
    rollback_breaking[0].writes = SchemaRange {
        minimum: 2,
        maximum: 2,
    };
    let candidate = build_manifest(
        "0.2.0",
        2,
        ReleaseChannel::Stable,
        false,
        vec![artifact],
        rollback_breaking,
    )
    .unwrap();
    assert!(matches!(
        plan_transition(&narrow_current, &candidate, false),
        Err(ReleaseError::RollbackIncompatible(state)) if state == "client_profiles"
    ));
}

#[test]
fn downgrade_requires_confirmation_and_consistent_sequence() {
    let artifact = ReleaseArtifact {
        kind: ArtifactKind::LinuxDeb,
        target: "x86_64-unknown-linux-gnu".to_owned(),
        file_name: "sirinvpn.deb".to_owned(),
        size_bytes: 1,
        sha256: "a".repeat(64),
    };
    let older = build_manifest(
        "0.1.0",
        1,
        ReleaseChannel::Stable,
        false,
        vec![artifact.clone()],
        compatibility(),
    )
    .unwrap();
    let newer = build_manifest(
        "0.2.0",
        2,
        ReleaseChannel::Stable,
        true,
        vec![artifact.clone()],
        compatibility(),
    )
    .unwrap();
    assert!(matches!(
        plan_transition(&newer, &older, false),
        Err(ReleaseError::RollbackConfirmationRequired)
    ));
    assert_eq!(
        plan_transition(&newer, &older, true).unwrap().direction,
        UpdateDirection::Rollback
    );
    assert!(
        plan_transition(&older, &newer, false)
            .unwrap()
            .security_update
    );

    let inconsistent = build_manifest(
        "0.3.0",
        1,
        ReleaseChannel::Stable,
        false,
        vec![artifact],
        compatibility(),
    )
    .unwrap();
    assert!(matches!(
        plan_transition(&newer, &inconsistent, false),
        Err(ReleaseError::VersionSequenceMismatch)
    ));
}

#[test]
fn manifest_rejects_unsafe_paths_duplicates_and_unknown_fields() {
    let artifact = ReleaseArtifact {
        kind: ArtifactKind::LinuxDeb,
        target: "x86_64-unknown-linux-gnu".to_owned(),
        file_name: "../sirinvpn.deb".to_owned(),
        size_bytes: 1,
        sha256: "a".repeat(64),
    };
    assert!(
        build_manifest(
            "0.1.0",
            1,
            ReleaseChannel::Stable,
            false,
            vec![artifact],
            compatibility(),
        )
        .is_err()
    );

    let directory = tempfile::tempdir().unwrap();
    let (manifest, _, _) = signed_release(directory.path(), "0.2.0", 2, compatibility());
    let mut value: serde_json::Value = serde_json::from_slice(&manifest).unwrap();
    value["unexpected"] = serde_json::json!(true);
    let mut bytes = serde_json::to_vec_pretty(&value).unwrap();
    bytes.push(b'\n');
    assert!(matches!(
        parse_manifest(&bytes),
        Err(ReleaseError::InvalidManifest)
    ));
}

#[test]
fn checked_in_compatibility_contract_is_canonical() {
    let contract = parse_compatibility_contract(include_bytes!(
        "../../../../release/state-compatibility.json"
    ))
    .unwrap();
    assert_eq!(contract.schema_version, 1);
    let state = |name: &str| {
        contract
            .states
            .iter()
            .find(|state| state.state == name)
            .unwrap()
    };
    assert_eq!(state("server_authorization").reads.maximum, 5);
    assert_eq!(state("server_configuration").reads.maximum, 8);
    assert_eq!(state("linux_tunnel_request").reads.maximum, 11);
    assert_eq!(state("linux_desired_connection").reads.maximum, 6);
    assert_eq!(state("linux_runtime_connection").reads.maximum, 5);
    assert_eq!(state("linux_key_rotation_journal").reads.maximum, 4);
    assert_eq!(state("desktop_connection_preferences").reads.maximum, 5);
    assert_eq!(state("android_persistent_tunnel").reads.maximum, 4);
    assert_eq!(state("android_wifi_trust").reads.maximum, 1);
    assert_eq!(state("android_wifi_tunnel").reads.maximum, 4);
    assert_eq!(contract.states[0].state, "android_identity_record");
    assert!(
        contract
            .states
            .windows(2)
            .all(|states| states[0].state < states[1].state)
    );
}
