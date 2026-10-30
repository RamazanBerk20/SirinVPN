use super::*;

#[test]
fn linux_desktop_updates_ignore_only_other_client_platform_state() {
    let root = tempfile::tempdir().unwrap();
    let appimage = root.path().join("SirinVPN.AppImage");
    let deb = root.path().join("SirinVPN.deb");
    fs::write(&appimage, "appimage").unwrap();
    fs::write(&deb, "deb").unwrap();
    let artifacts = vec![
        ReleaseArtifact::from_path(ArtifactKind::LinuxAppImage, TARGET, &appimage).unwrap(),
        ReleaseArtifact::from_path(ArtifactKind::LinuxDeb, TARGET, &deb).unwrap(),
    ];
    let states = crate::parse_compatibility_contract(include_bytes!(
        "../../../../../release/state-compatibility.json"
    ))
    .unwrap()
    .states;
    let manifest = |version, sequence, states| {
        build_manifest(
            version,
            sequence,
            ReleaseChannel::Stable,
            false,
            artifacts.clone(),
            states,
        )
        .unwrap()
    };
    let current = manifest("1.0.0", 1, states.clone());
    let incompatible = |name: &str| {
        let mut states = states.clone();
        let state = states.iter_mut().find(|state| state.state == name).unwrap();
        let next = state.reads.maximum.max(state.writes.maximum) + 1;
        let range = SchemaRange {
            minimum: next,
            maximum: next,
        };
        state.reads = range;
        state.writes = range;
        manifest("1.1.0", 2, states)
    };
    for kind in [ArtifactKind::LinuxDeb, ArtifactKind::LinuxAppImage] {
        for other_platform in ["android_profile_journal", "windows_identity_record"] {
            assert!(
                plan_artifact_transition(&current, &incompatible(other_platform), kind, false)
                    .is_ok()
            );
        }
        for shared in [
            "linux_identity_record",
            "desktop_connection_preferences",
            "device_backup_payload",
            "server_configuration",
        ] {
            assert!(matches!(
                plan_artifact_transition(&current, &incompatible(shared), kind, false),
                Err(ReleaseError::ForwardIncompatible(state)) if state == shared
            ));
        }
    }
}

#[test]
fn preshared_key_state_never_crosses_to_or_from_a_release_that_drops_the_key() {
    let root = tempfile::tempdir().unwrap();
    let deb = root.path().join("SirinVPN.deb");
    fs::write(&deb, "deb").unwrap();
    let artifacts = vec![ReleaseArtifact::from_path(ArtifactKind::LinuxDeb, TARGET, &deb).unwrap()];
    let states = crate::parse_compatibility_contract(include_bytes!(
        "../../../../../release/state-compatibility.json"
    ))
    .unwrap()
    .states;
    let manifest = |version, sequence, states| {
        build_manifest(
            version,
            sequence,
            ReleaseChannel::Stable,
            false,
            artifacts.clone(),
            states,
        )
        .unwrap()
    };
    // Declarations before preshared keys: such a reader would silently drop the key.
    let mut previous = states.clone();
    for state in &mut previous {
        if matches!(
            state.state.as_str(),
            "linux_identity_record" | "device_backup_payload"
        ) {
            state.reads.maximum = 2;
            state.writes.maximum = 2;
        }
    }
    let previous = manifest("1.0.0", 1, previous);
    let current = manifest("1.1.0", 2, states);
    // The updater keeps its rollback guarantee: neither direction is planned.
    assert!(matches!(
        plan_artifact_transition(&previous, &current, ArtifactKind::LinuxDeb, false),
        Err(ReleaseError::RollbackIncompatible(state)) if state == "device_backup_payload"
    ));
    assert!(matches!(
        plan_artifact_transition(&current, &previous, ArtifactKind::LinuxDeb, true),
        Err(ReleaseError::ForwardIncompatible(state)) if state == "device_backup_payload"
    ));
}
