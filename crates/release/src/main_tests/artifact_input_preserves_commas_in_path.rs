use super::*;

#[test]
fn artifact_input_preserves_commas_in_path() {
    let parsed: ArtifactInput = "linux_deb,x86_64-unknown-linux-gnu,/tmp/a,b.deb"
        .parse()
        .unwrap();
    assert_eq!(parsed.kind, ArtifactKind::LinuxDeb);
    assert_eq!(parsed.target, "x86_64-unknown-linux-gnu");
    assert_eq!(parsed.path, PathBuf::from("/tmp/a,b.deb"));
}

#[test]
fn installed_state_cli_preserves_the_exact_artifact_slot() {
    let cli = Cli::try_parse_from([
        "sirinvpn-release",
        "state",
        "commit-installation",
        "--manifest",
        "/tmp/manifest.json",
        "--signature",
        "/tmp/signature.json",
        "--trusted-public-key",
        "/tmp/public.pem",
        "--artifact-directory",
        "/tmp/release",
        "--artifact-kind",
        "linux_deb",
        "--artifact-target",
        "x86_64-unknown-linux-gnu",
        "--allow-rollback",
    ])
    .unwrap();
    let Command::State(StateArguments {
        command: StateCommand::CommitInstallation(arguments),
    }) = cli.command
    else {
        panic!("expected the installed-state commit command")
    };
    assert_eq!(arguments.artifact_kind, ArtifactKind::LinuxDeb);
    assert_eq!(arguments.artifact_target, "x86_64-unknown-linux-gnu");
    assert_eq!(
        arguments.trusted_public_key,
        Some(PathBuf::from("/tmp/public.pem"))
    );
    assert!(arguments.allow_rollback);
}

#[test]
fn transactional_debian_cli_has_no_network_or_package_override() {
    let cli = Cli::try_parse_from([
        "sirinvpn-release",
        "state",
        "install-debian",
        "--manifest",
        "/media/offline/sirinvpn-release.json",
        "--signature",
        "/media/offline/sirinvpn-release.sig.json",
        "--trusted-public-key",
        "/media/offline/public.pem",
        "--artifact-directory",
        "/media/offline",
        "--artifact-target",
        "x86_64-unknown-linux-gnu",
    ])
    .unwrap();
    let Command::State(StateArguments {
        command: StateCommand::InstallDebian(arguments),
    }) = cli.command
    else {
        panic!("expected the transactional Debian install command")
    };
    assert_eq!(
        arguments.artifact_directory,
        PathBuf::from("/media/offline")
    );
    assert_eq!(arguments.artifact_target, "x86_64-unknown-linux-gnu");
    assert_eq!(
        arguments.trusted_public_key,
        Some(PathBuf::from("/media/offline/public.pem"))
    );
    assert!(!arguments.allow_rollback);

    let recovered = Cli::try_parse_from(["sirinvpn-release", "state", "recover-debian"]).unwrap();
    assert!(matches!(
        recovered.command,
        Command::State(StateArguments {
            command: StateCommand::RecoverDebian
        })
    ));
}

#[test]
fn trusted_state_and_policy_commands_need_no_caller_supplied_root() {
    let trusted = Cli::try_parse_from([
        "sirinvpn-release",
        "state",
        "install-debian",
        "--manifest",
        "/media/offline/sirinvpn-release.json",
        "--signature",
        "/media/offline/sirinvpn-release.sig.json",
        "--artifact-directory",
        "/media/offline",
        "--artifact-target",
        "x86_64-unknown-linux-gnu",
    ])
    .unwrap();
    let Command::State(StateArguments {
        command: StateCommand::InstallDebian(arguments),
    }) = trusted.command
    else {
        panic!("expected the trusted Debian install command")
    };
    assert_eq!(arguments.trusted_public_key, None);

    let apply = Cli::try_parse_from([
        "sirinvpn-release",
        "state",
        "apply-trust",
        "--policy",
        "/media/offline/sirinvpn-release-trust.json",
        "--signature",
        "/media/offline/sirinvpn-release-trust.sig.json",
    ])
    .unwrap();
    assert!(matches!(
        apply.command,
        Command::State(StateArguments {
            command: StateCommand::ApplyTrust(_)
        })
    ));

    let root = Cli::try_parse_from(["sirinvpn-release", "trust", "root"]).unwrap();
    assert!(matches!(
        root.command,
        Command::Trust(TrustArguments {
            command: TrustCommand::Root
        })
    ));
}

#[test]
fn pair_write_refuses_overwrite_and_removes_partial_first_output() {
    let directory = tempfile::tempdir().unwrap();
    let first = directory.path().join("first");
    let second = directory.path().join("second");
    fs::write(&second, b"existing").unwrap();
    assert!(write_pair_new(&first, b"new", 0o600, &second, b"new", 0o644).is_err());
    assert!(!first.exists());
    assert_eq!(fs::read(second).unwrap(), b"existing");
}

#[test]
fn signing_refuses_a_group_or_world_accessible_private_key() {
    let directory = tempfile::tempdir().unwrap();
    let key = directory.path().join("private.pem");
    fs::write(&key, b"not even parsed").unwrap();
    fs::set_permissions(&key, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(
        read_private_key(&key)
            .unwrap_err()
            .to_string()
            .contains("must not be accessible")
    );
}

#[test]
fn command_path_creates_verifies_and_plans_a_release() {
    let directory = tempfile::tempdir().unwrap();
    let private_key = directory.path().join("private.pem");
    let public_key = directory.path().join("public.pem");
    keygen(
        KeygenArguments {
            private_key: private_key.clone(),
            public_key: public_key.clone(),
        },
        false,
    )
    .unwrap();
    assert_eq!(
        fs::metadata(&private_key).unwrap().permissions().mode() & 0o777,
        0o600
    );

    let artifact = directory.path().join("sirinvpn-server");
    fs::write(&artifact, b"bounded test artifact").unwrap();
    let compatibility = directory.path().join("compatibility.json");
    let contract = sirinvpn_release::CompatibilityContract {
        schema_version: 1,
        states: vec![sirinvpn_release::StateCompatibility {
            state: "server_configuration".to_owned(),
            reads: sirinvpn_release::SchemaRange {
                minimum: 1,
                maximum: 1,
            },
            writes: sirinvpn_release::SchemaRange {
                minimum: 1,
                maximum: 1,
            },
        }],
    };
    fs::write(
        &compatibility,
        sirinvpn_release::encode_compatibility_contract(&contract).unwrap(),
    )
    .unwrap();

    let current_manifest = directory.path().join("current.json");
    let current_signature = directory.path().join("current.sig.json");
    let candidate_manifest = directory.path().join("candidate.json");
    let candidate_signature = directory.path().join("candidate.sig.json");
    let artifact_input = ArtifactInput {
        kind: ArtifactKind::ServerElf,
        target: "x86_64-unknown-linux-gnu".to_owned(),
        path: artifact,
    };
    create(
        CreateArguments {
            version: "0.1.0".to_owned(),
            sequence: 1,
            channel: ReleaseChannel::Stable,
            security_update: false,
            artifact: vec![artifact_input.clone()],
            compatibility: compatibility.clone(),
            private_key: private_key.clone(),
            manifest: current_manifest.clone(),
            signature: current_signature.clone(),
        },
        false,
    )
    .unwrap();
    create(
        CreateArguments {
            version: "0.2.0".to_owned(),
            sequence: 2,
            channel: ReleaseChannel::Stable,
            security_update: true,
            artifact: vec![artifact_input],
            compatibility,
            private_key,
            manifest: candidate_manifest.clone(),
            signature: candidate_signature.clone(),
        },
        false,
    )
    .unwrap();
    verify(
        VerifyArguments {
            manifest: candidate_manifest.clone(),
            signature: candidate_signature.clone(),
            trusted_public_key: public_key.clone(),
            artifact_directory: directory.path().to_owned(),
        },
        false,
    )
    .unwrap();
    plan(
        PlanArguments {
            current_manifest,
            current_signature,
            candidate_manifest,
            candidate_signature,
            trusted_public_key: public_key,
            candidate_artifact_directory: directory.path().to_owned(),
            allow_rollback: false,
        },
        false,
    )
    .unwrap();
}
