use super::*;
use std::{os::unix::fs::PermissionsExt, process::Command};

#[test]
fn a_fresh_vps_has_an_explicit_absent_record_without_an_empty_binary_response() {
    let directory = tempfile::tempdir().unwrap();
    let missing = directory
        .path()
        .join("missing-release-directory/receipt.json");
    let result = Command::new("/bin/sh")
        .args([
            "-c",
            &optional_record_command(missing.to_str().unwrap(), 64),
        ])
        .output()
        .unwrap();
    assert!(result.status.success());
    assert_eq!(result.stdout, [0]);
    assert_eq!(decode_optional_record(&result.stdout).unwrap(), None);
    for malformed in [&b""[..], &[1], &[0, 1], &[2, 1]] {
        assert!(decode_optional_record(malformed).is_err());
    }
    assert_eq!(
        decode_optional_record(b"\x01public record\n").unwrap(),
        Some(b"public record\n".to_vec())
    );
}

#[test]
fn repair_uses_committed_signed_bytes_and_never_falls_back_to_the_desktop_bundle() {
    use sirinvpn_release::{
        InstalledReleaseReceipt, ReleaseArtifact, ReleaseChannel, SchemaRange, SignedReleaseRecord,
        StateCompatibility,
    };
    let (private, public) = sirinvpn_release::generate_signing_keypair().unwrap();
    let mut bytes = vec![0; 32];
    bytes[..6].copy_from_slice(b"\x7fELF\x02\x01");
    bytes[18] = 62;
    let digest = hex::encode(Sha256::digest(&bytes));
    let artifact = ReleaseArtifact {
        kind: ArtifactKind::ServerElf,
        target: "x86_64-unknown-linux-gnu".into(),
        file_name: "sirinvpn-server".into(),
        size_bytes: bytes.len() as u64,
        sha256: digest.clone(),
    };
    let manifest = sirinvpn_release::build_manifest(
        "99.0.0",
        99,
        ReleaseChannel::Stable,
        true,
        vec![artifact.clone()],
        vec![StateCompatibility {
            state: "linux_release_receipt".into(),
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
    let signature = sirinvpn_release::sign_manifest(
        &sirinvpn_release::encode_manifest(&manifest).unwrap(),
        &private,
    )
    .unwrap();
    let record = SignedReleaseRecord {
        manifest,
        signature: sirinvpn_release::parse_signature(&signature).unwrap(),
    };
    let receipt = InstalledReleaseReceipt {
        schema_version: 1,
        trusted_public_key_pem: public,
        active_release: record.clone(),
        highest_accepted_release: record,
        active_artifact: artifact,
    };
    let mut receipt = serde_json::to_vec_pretty(&receipt).unwrap();
    receipt.push(b'\n');
    let discovery = ServerDiscovery {
        os_id: "debian".into(),
        os_version: "13".into(),
        architecture: "x86_64".into(),
        default_interface: "eth0".into(),
        ipv6_default_interface: None,
        ssh_server_port: 22,
        ipv4_available: true,
        ipv6_available: false,
        nftables_available: true,
        wireguard_available: true,
        unbound_installed: true,
        sirinvpn_installed: true,
    };
    let unavailable_bundle =
        ServerBinarySource::Exact(PathBuf::from("/no-desktop-bundle-is-needed"));
    let prepared = prepare_from_records(
        &unavailable_bundle,
        &discovery,
        Some(receipt.clone()),
        None,
        |path| {
            assert_eq!(
                path,
                format!("{RELEASE_DIRECTORY}/packages/{digest}.server")
            );
            Ok(bytes.clone())
        },
    )
    .unwrap();
    assert!(prepared.preserves_signed_release);
    assert_eq!(prepared.bytes, bytes);
    assert_eq!(prepared.sha256, digest);
    assert!(
        prepare_from_records(
            &unavailable_bundle,
            &discovery,
            Some(receipt.clone()),
            None,
            |_| Ok(vec![0; 32])
        )
        .is_err()
    );
    receipt[0] = b'!';
    assert!(
        prepare_from_records(
            &unavailable_bundle,
            &discovery,
            Some(receipt),
            None,
            |_| panic!("an invalid receipt must not select any executable")
        )
        .is_err()
    );
    let policy_without_baseline = prepare_from_records(
        &unavailable_bundle,
        &discovery,
        None,
        Some(b"protected policy".to_vec()),
        |_| panic!("no committed artifact exists"),
    );
    assert!(
        matches!(policy_without_baseline, Err(InstallerError::InvalidInput(message)) if message.contains("signing policy"))
    );
}

#[test]
#[ignore = "runs only in the disposable root container"]
fn isolated_root_staging_rejects_policy_races_and_artifact_swaps_before_execution() {
    assert_eq!(
        std::env::var("SIRINVPN_POLICY_ISOLATED").as_deref(),
        Ok("1")
    );
    assert_eq!(
        Command::new("id").arg("-u").output().unwrap().stdout,
        b"0\n"
    );
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().to_str().unwrap();
    let release = directory.path().join("release");
    fs::create_dir(&release).unwrap();
    fs::set_permissions(&release, fs::Permissions::from_mode(0o700)).unwrap();
    let trust = release.join("trust.json");
    fs::write(&trust, b"inspected public signing policy").unwrap();
    fs::set_permissions(&trust, fs::Permissions::from_mode(0o600)).unwrap();
    let read_optional = |path: &Path, maximum: usize| {
        Command::new("/bin/sh")
            .args([
                "-c",
                &optional_record_command(path.to_str().unwrap(), maximum)
                    .replace(RELEASE_DIRECTORY, release.to_str().unwrap()),
            ])
            .output()
            .unwrap()
    };
    let record = read_optional(&trust, 64);
    assert!(record.status.success());
    assert_eq!(
        decode_optional_record(&record.stdout).unwrap(),
        Some(b"inspected public signing policy".to_vec())
    );
    assert!(!read_optional(&trust, 8).status.success());
    let empty = release.join("empty.json");
    fs::write(&empty, b"").unwrap();
    fs::set_permissions(&empty, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(!read_optional(&empty, 64).status.success());
    fs::remove_file(&empty).unwrap();
    std::os::unix::fs::symlink(&trust, &empty).unwrap();
    assert!(!read_optional(&empty, 64).status.success());
    fs::remove_file(&empty).unwrap();
    let source = directory.path().join("candidate");
    let executed = directory.path().join("executed");
    let binary = format!(
        r#"#!/bin/sh
printf 'called\n' >>'{root}/executed'
if [ "$1" = release ]; then printf '{{"server_handoff_guard":1,"server_maintenance_guard":1}}\n'; fi
# Replacing the SSH user's source cannot replace the private verified copy.
printf 'changed after staging\n' >'{root}/candidate'
"#
    );
    let prepared = PreparedArtifact {
        bytes: binary.as_bytes().to_vec(),
        sha256: hex::encode(Sha256::digest(binary.as_bytes())),
        state_guard: format!(
            "{}\n{}",
            record_guard("receipt.json", None),
            record_guard("trust.json", Some(b"inspected public signing policy"))
        ),
        preserves_signed_release: false,
    };
    let script = format!(
        "set -eu\numask 077\n{}",
        prepared.root_preflight(source.to_str().unwrap(), "fixture", true)
    )
    .replace(RELEASE_DIRECTORY, release.to_str().unwrap())
    .replace(EXECUTION_DIRECTORY, root);
    let run = || {
        Command::new("/bin/sh")
            .arg("-c")
            .arg(&script)
            .output()
            .unwrap()
    };
    fs::write(&source, b"changed before staging").unwrap();
    assert!(!run().status.success());
    assert!(!executed.exists());
    fs::write(&source, &binary).unwrap();
    fs::write(&trust, b"a newer public signing policy").unwrap();
    assert!(!run().status.success());
    assert!(!executed.exists());
    fs::write(&trust, b"inspected public signing policy").unwrap();
    fs::write(release.join("receipt.json"), b"another baseline committed").unwrap();
    assert!(!run().status.success());
    assert!(!executed.exists());
    fs::remove_file(release.join("receipt.json")).unwrap();
    let result = run();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(fs::read_to_string(executed).unwrap(), "called\ncalled\n");
    assert_eq!(
        fs::read_to_string(source).unwrap(),
        "changed after staging\n"
    );
}

#[test]
#[ignore = "requires a disposable root container with /run mounted noexec"]
fn isolated_root_staging_runs_when_run_is_noexec() {
    assert_eq!(
        std::env::var("SIRINVPN_POLICY_ISOLATED").as_deref(),
        Ok("1")
    );
    assert_eq!(
        Command::new("id").arg("-u").output().unwrap().stdout,
        b"0\n"
    );
    let directory = tempfile::Builder::new()
        .prefix("sirinvpn-noexec-")
        .tempdir_in("/run")
        .unwrap();
    let source = directory.path().join("candidate");
    let binary = b"#!/bin/sh\nif [ \"$1\" = release ]; then printf '%s\\n' '{\"server_handoff_guard\":1,\"server_maintenance_guard\":1}'; fi\n";
    fs::write(&source, binary).unwrap();
    fs::set_permissions(&source, fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(
        Command::new(&source).output().unwrap_err().kind(),
        std::io::ErrorKind::PermissionDenied
    );
    let prepared = PreparedArtifact {
        bytes: binary.to_vec(),
        sha256: hex::encode(Sha256::digest(binary)),
        state_guard: "true".to_owned(),
        preserves_signed_release: false,
    };
    let script = format!(
        "set -eu\numask 077\n{}\nprintf '%s\\n' \"$STAGING_DIR\"",
        prepared.root_preflight(source.to_str().unwrap(), "noexec-fixture", true)
    );
    let result = Command::new("/bin/sh")
        .args(["-c", &script])
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let staging = String::from_utf8(result.stdout).unwrap();
    assert!(
        staging
            .trim()
            .starts_with("/usr/local/lib/.sirinvpn-stage-noexec-fixture.")
    );
    assert!(
        !Path::new(staging.trim()).exists(),
        "staging must be removed on exit"
    );
}
