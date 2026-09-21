use super::*;

#[test]
fn same_signed_release_can_rebind_to_another_declared_artifact() {
    let root = tempfile::tempdir().unwrap();
    let directory = root.path().join("release");
    fs::create_dir(&directory).unwrap();
    let appimage = directory.join("SirinVPN.AppImage");
    let deb = directory.join("SirinVPN.deb");
    fs::write(&appimage, "appimage").unwrap();
    fs::write(&deb, "deb").unwrap();
    let keys = test_keys();
    let manifest = build_manifest(
        "0.1.0",
        1,
        ReleaseChannel::Stable,
        false,
        vec![
            ReleaseArtifact::from_path(ArtifactKind::LinuxAppImage, TARGET, &appimage).unwrap(),
            ReleaseArtifact::from_path(ArtifactKind::LinuxDeb, TARGET, &deb).unwrap(),
        ],
        compatibility(),
    )
    .unwrap();
    let manifest = encode_manifest(&manifest).unwrap();
    let signature = sign_manifest(&manifest, &keys.private).unwrap();
    let store = InstalledReleaseStore::new(root.path().join("state"));

    store
        .commit_installation(
            &manifest,
            &signature,
            &keys.public,
            &directory,
            ArtifactKind::LinuxAppImage,
            TARGET,
            false,
        )
        .unwrap();
    let rebound = store
        .commit_installation(
            &manifest,
            &signature,
            &keys.public,
            &directory,
            ArtifactKind::LinuxDeb,
            TARGET,
            false,
        )
        .unwrap();
    assert_eq!(rebound.action, InstallationDecisionKind::Rebind);
    assert_eq!(rebound.state.active_artifact.kind, ArtifactKind::LinuxDeb);
    assert_eq!(rebound.state.highest_accepted_release_sequence, 1);
}
