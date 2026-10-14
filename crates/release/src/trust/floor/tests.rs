use super::*;
use crate::{
    ArtifactKind, ReleaseArtifact, SchemaRange, StateCompatibility, build_manifest,
    encode_manifest, generate_signing_keypair, sign_manifest,
};

const TARGET: &str = "x86_64-unknown-linux-gnu";

struct Keys {
    private: zeroize::Zeroizing<String>,
    public: String,
}

fn keys() -> Keys {
    let (private, public) = generate_signing_keypair().unwrap();
    Keys { private, public }
}

fn signed_policy(
    root: &Keys,
    sequence: u64,
    active: &[&Keys],
    revoked: Vec<String>,
) -> (Vec<u8>, Vec<u8>) {
    let policy = build_trust_policy(
        sequence,
        active.iter().map(|key| key.public.clone()).collect(),
        revoked,
    )
    .unwrap();
    let policy = encode_trust_policy(&policy).unwrap();
    let signature = sign_trust_policy(&policy, &root.private).unwrap();
    (policy, signature)
}

fn manifest(version: &str, sequence: u64, channel: ReleaseChannel, file: &str) -> ReleaseManifest {
    build_manifest(
        version,
        sequence,
        channel,
        false,
        vec![ReleaseArtifact {
            kind: ArtifactKind::ServerElf,
            target: TARGET.to_owned(),
            file_name: file.to_owned(),
            size_bytes: 32,
            sha256: "a".repeat(64),
        }],
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
    )
    .unwrap()
}

#[test]
fn a_fresh_vps_cannot_adopt_a_policy_older_than_this_devices_own() {
    let root = keys();
    let retired = keys();
    let current = keys();
    let retired_id = public_key_id(&retired.public).unwrap();
    let directory = tempfile::tempdir().unwrap();
    let store = InstalledReleaseStore::new(directory.path().join("state"));

    // No local state: the served policy only has to verify under the root.
    let empty = store.release_floor_with_root(&root.public).unwrap();
    assert!(empty.is_empty());
    assert!(!directory.path().join("state").exists());
    let (stale, stale_signature) = signed_policy(&root, 1, &[&retired], vec![]);
    assert_eq!(
        empty
            .verify_trust_policy_with_root(&stale, &stale_signature, &root.public)
            .unwrap()
            .policy
            .sequence,
        1
    );

    let (local, local_signature) = signed_policy(&root, 2, &[&current], vec![retired_id.clone()]);
    store
        .apply_trust_policy_with_root(&local, &local_signature, &root.public)
        .unwrap();
    let floor = store.release_floor_with_root(&root.public).unwrap();
    assert!(!floor.is_empty());
    assert_eq!(
        floor.trust_record(),
        Some(fs::read(store.trust_path()).unwrap().as_slice())
    );

    // A validly root-signed but superseded policy that still lists the
    // revoked key is refused, as is a newer one that forgets the revocation.
    assert!(matches!(
        floor.verify_trust_policy_with_root(&stale, &stale_signature, &root.public),
        Err(ReleaseError::TrustPolicyRollback)
    ));
    let (forgotten, forgotten_signature) = signed_policy(&root, 3, &[&current, &retired], vec![]);
    assert!(matches!(
        floor.verify_trust_policy_with_root(&forgotten, &forgotten_signature, &root.public),
        Err(ReleaseError::TrustPolicyUnrevokesKey)
    ));
    let (collision, collision_signature) =
        signed_policy(&root, 2, &[&current, &keys()], vec![retired_id.clone()]);
    assert!(matches!(
        floor.verify_trust_policy_with_root(&collision, &collision_signature, &root.public),
        Err(ReleaseError::TrustPolicySequenceCollision)
    ));

    for (policy, signature, sequence) in [(local.clone(), local_signature.clone(), 2), {
        let (newer, newer_signature) = signed_policy(&root, 3, &[&current], vec![retired_id]);
        (newer, newer_signature, 3)
    }] {
        assert_eq!(
            floor
                .verify_trust_policy_with_root(&policy, &signature, &root.public)
                .unwrap()
                .policy
                .sequence,
            sequence
        );
    }

    // The production entry point verifies under the bundled root only.
    assert!(matches!(
        floor.verify_trust_policy(&local, &local_signature),
        Err(ReleaseError::TrustRootMismatch)
    ));
}

#[test]
fn a_fresh_vps_cannot_adopt_a_release_this_device_already_superseded() {
    let accepted = manifest("1.5.0", 5, ReleaseChannel::Stable, "sirinvpn-server");
    let accepted_digest = "b".repeat(64);
    let floor = LocalReleaseFloor {
        trust: None,
        highest_accepted: Some(AcceptedRelease {
            channel: ReleaseChannel::Stable,
            sequence: 5,
            manifest_sha256: accepted_digest.clone(),
        }),
    };
    assert!(matches!(
        floor.verify_release(
            &manifest("1.4.0", 4, ReleaseChannel::Stable, "sirinvpn-server"),
            &"c".repeat(64)
        ),
        Err(ReleaseError::BelowHighestAcceptedRelease)
    ));
    assert!(matches!(
        floor.verify_release(
            &manifest("1.5.0", 5, ReleaseChannel::Stable, "other-server"),
            &"c".repeat(64)
        ),
        Err(ReleaseError::ReleaseSequenceCollision)
    ));
    floor.verify_release(&accepted, &accepted_digest).unwrap();
    floor
        .verify_release(
            &manifest("1.6.0", 6, ReleaseChannel::Stable, "sirinvpn-server"),
            &"c".repeat(64),
        )
        .unwrap();
    // Each channel has its own sequence.
    floor
        .verify_release(
            &manifest("1.0.0", 1, ReleaseChannel::Preview, "sirinvpn-server"),
            &"c".repeat(64),
        )
        .unwrap();
    LocalReleaseFloor::default()
        .verify_release(
            &manifest("1.0.0", 1, ReleaseChannel::Stable, "sirinvpn-server"),
            &"c".repeat(64),
        )
        .unwrap();
}

#[test]
fn the_store_floor_reports_the_highest_accepted_release_without_writing() {
    let release_keys = keys();
    let directory = tempfile::tempdir().unwrap();
    let artifacts = directory.path().join("artifacts");
    fs::create_dir(&artifacts).unwrap();
    let artifact_path = artifacts.join("SirinVPN_1.5.0_amd64.AppImage");
    fs::write(&artifact_path, b"authenticated appimage").unwrap();
    let artifact =
        ReleaseArtifact::from_path(ArtifactKind::LinuxAppImage, TARGET, &artifact_path).unwrap();
    let mut release = manifest("1.5.0", 5, ReleaseChannel::Stable, "unused");
    release.artifacts = vec![artifact];
    let release = encode_manifest(&release).unwrap();
    let signature = sign_manifest(&release, &release_keys.private).unwrap();
    let store = InstalledReleaseStore::new(directory.path().join("state"));
    store
        .commit_installation(
            &release,
            &signature,
            &release_keys.public,
            &artifacts,
            ArtifactKind::LinuxAppImage,
            TARGET,
            false,
        )
        .unwrap();
    let receipt = fs::read(store.receipt_path()).unwrap();

    let floor = store.release_floor().unwrap();
    assert_eq!(floor.trust_record(), None);
    let highest = floor.highest_accepted.as_ref().unwrap();
    assert_eq!(highest.channel, ReleaseChannel::Stable);
    assert_eq!(highest.sequence, 5);
    assert_eq!(
        highest.manifest_sha256,
        hex::encode(Sha256::digest(&release))
    );
    assert_eq!(fs::read(store.receipt_path()).unwrap(), receipt);
    assert!(!store.trust_path().exists());
}
