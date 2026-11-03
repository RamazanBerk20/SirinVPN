use super::*;
use sirinvpn_release::{SchemaRange, StateCompatibility, verify_release_notes};

#[test]
fn notes_command_binds_the_manifest_signer() {
    let directory = tempfile::tempdir().unwrap();
    let path = |name: &str| directory.path().join(name);
    fs::write(path("app.deb"), b"package").unwrap();
    let artifact = ReleaseArtifact::from_path(
        ArtifactKind::LinuxDeb,
        "x86_64-unknown-linux-gnu",
        &path("app.deb"),
    )
    .unwrap();
    let range = SchemaRange {
        minimum: 1,
        maximum: 1,
    };
    let state = StateCompatibility {
        state: "client_profiles".to_owned(),
        reads: range,
        writes: range,
    };
    let manifest = encode_manifest(
        &build_manifest(
            "0.2.0",
            2,
            ReleaseChannel::Stable,
            false,
            vec![artifact],
            vec![state],
        )
        .unwrap(),
    )
    .unwrap();
    let (private, public) = generate_signing_keypair().unwrap();
    let (other, _) = generate_signing_keypair().unwrap();
    fs::write(path("manifest.json"), &manifest).unwrap();
    fs::write(
        path("signature.json"),
        sign_manifest(&manifest, &private).unwrap(),
    )
    .unwrap();
    fs::write(path("summary.txt"), "Faster reconnects after sleep.\n").unwrap();
    for (name, key) in [("private.pem", &private), ("other.pem", &other)] {
        fs::write(path(name), key.as_bytes()).unwrap();
        fs::set_permissions(path(name), fs::Permissions::from_mode(0o600)).unwrap();
    }
    let arguments = |key: &str, output: &str| {
        let Command::Notes(arguments) = Cli::try_parse_from([
            "sirinvpn-release",
            "notes",
            "--manifest",
            path("manifest.json").to_str().unwrap(),
            "--signature",
            path("signature.json").to_str().unwrap(),
            "--summary",
            path("summary.txt").to_str().unwrap(),
            "--private-key",
            path(key).to_str().unwrap(),
            "--output",
            path(output).to_str().unwrap(),
        ])
        .unwrap()
        .command
        else {
            panic!("expected the notes command")
        };
        arguments
    };

    assert!(notes::notes(arguments("other.pem", "wrong.json"), true).is_err());
    assert!(!path("wrong.json").exists());
    notes::notes(arguments("private.pem", "notes.json"), true).unwrap();
    let notes = fs::read(path("notes.json")).unwrap();
    let signature = fs::read(path("signature.json")).unwrap();
    assert_eq!(
        verify_release_notes(&notes, &manifest, &signature, &public).unwrap(),
        "Faster reconnects after sleep."
    );
}
