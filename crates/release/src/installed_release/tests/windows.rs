use super::*;

const WINDOWS: &str = "x86_64-pc-windows-msvc";

#[test]
fn windows_installer_receipts_keep_signature_binding_and_rollback_high_watermark() {
    let root = tempfile::tempdir().unwrap();
    let keys = test_keys();
    let store = InstalledReleaseStore::new(root.path().join("state"));
    let bundle = |version: &str, sequence, android_schema| {
        let directory = root.path().join(version);
        fs::create_dir(&directory).unwrap();
        let path = directory.join("SirinVPN-setup.exe");
        fs::write(
            &path,
            format!("signed Windows installer test fixture {version}"),
        )
        .unwrap();
        let artifact =
            ReleaseArtifact::from_path(ArtifactKind::WindowsInstaller, WINDOWS, &path).unwrap();
        let mut states = compatibility();
        states.push(StateCompatibility {
            state: "windows_service_session".into(),
            reads: SchemaRange {
                minimum: 1,
                maximum: 1,
            },
            writes: SchemaRange {
                minimum: 1,
                maximum: 1,
            },
        });
        states.push(StateCompatibility {
            state: "android_profile_journal".into(),
            reads: SchemaRange {
                minimum: android_schema,
                maximum: android_schema,
            },
            writes: SchemaRange {
                minimum: android_schema,
                maximum: android_schema,
            },
        });
        let manifest = encode_manifest(
            &build_manifest(
                version,
                sequence,
                ReleaseChannel::Stable,
                false,
                vec![artifact],
                states,
            )
            .unwrap(),
        )
        .unwrap();
        let signature = sign_manifest(&manifest, &keys.private).unwrap();
        TestRelease {
            directory,
            manifest,
            signature,
        }
    };
    let first = bundle("1.0.0", 1, 1);
    let next = bundle("1.1.0", 2, 2);
    let install = |bundle: &TestRelease, rollback| {
        store.commit_installation(
            &bundle.manifest,
            &bundle.signature,
            &keys.public,
            &bundle.directory,
            ArtifactKind::WindowsInstaller,
            WINDOWS,
            rollback,
        )
    };
    install(&first, false).unwrap();
    let upgraded = install(&next, false).unwrap();
    assert_eq!(upgraded.action, InstallationDecisionKind::Upgrade);
    assert!(
        store
            .cached_artifact_path(&upgraded.state.active_artifact)
            .unwrap()
            .extension()
            .is_some_and(|suffix| suffix == "exe")
    );
    assert!(install(&first, false).is_err());
    let rollback = install(&first, true).unwrap();
    assert_eq!(rollback.action, InstallationDecisionKind::Rollback);
    assert_eq!(rollback.state.active_release_sequence, 1);
    assert_eq!(rollback.state.highest_accepted_release_sequence, 2);
    assert_eq!(fs::read_dir(store.package_directory()).unwrap().count(), 1);
    fs::write(next.directory.join("SirinVPN-setup.exe"), b"tampered").unwrap();
    assert!(install(&next, false).is_err());
    assert_eq!(store.inspect().unwrap().unwrap(), rollback.state);
}
