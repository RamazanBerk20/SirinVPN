use super::*;

use std::fs;
#[cfg(unix)]
use std::os::unix::fs::symlink;

fn compatibility() -> Vec<StateCompatibility> {
    vec![
        StateCompatibility {
            state: "client_profiles".to_owned(),
            reads: SchemaRange {
                minimum: 1,
                maximum: 2,
            },
            writes: SchemaRange {
                minimum: 1,
                maximum: 1,
            },
        },
        StateCompatibility {
            state: "server_configuration".to_owned(),
            reads: SchemaRange {
                minimum: 1,
                maximum: 5,
            },
            writes: SchemaRange {
                minimum: 1,
                maximum: 5,
            },
        },
    ]
}

fn signed_release(
    directory: &Path,
    version: &str,
    sequence: u64,
    states: Vec<StateCompatibility>,
) -> (Vec<u8>, Vec<u8>, String) {
    let artifact_path = directory.join(format!("sirinvpn-{sequence}.AppImage"));
    fs::write(&artifact_path, format!("release {sequence}")).unwrap();
    let artifact = ReleaseArtifact::from_path(
        ArtifactKind::LinuxAppImage,
        "x86_64-unknown-linux-gnu",
        &artifact_path,
    )
    .unwrap();
    let manifest = build_manifest(
        version,
        sequence,
        ReleaseChannel::Stable,
        false,
        vec![artifact],
        states,
    )
    .unwrap();
    let manifest_bytes = encode_manifest(&manifest).unwrap();
    let (private, public) = generate_signing_keypair().unwrap();
    let signature = sign_manifest(&manifest_bytes, &private).unwrap();
    (manifest_bytes, signature, public)
}

mod signed_release_verifies_every_artifact;
