use super::*;
use crate::{
    ArtifactKind, ReleaseArtifact, ReleaseChannel, SchemaRange, StateCompatibility, build_manifest,
    build_trust_policy, encode_manifest, encode_trust_policy, generate_signing_keypair,
    sign_manifest, sign_trust_policy, verify_release_notes_with_trust_policy, verify_trust_policy,
};

const SUMMARY: &str = "Reconnects faster after sleep and fixes a rare DNS stall.";

struct Release {
    manifest: Vec<u8>,
    signature: Vec<u8>,
    private: String,
    public: String,
}

fn release(sequence: u64, private: Option<(&str, &str)>) -> Release {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("sirinvpn.AppImage");
    std::fs::write(&path, format!("release {sequence}")).unwrap();
    let artifact = ReleaseArtifact::from_path(
        ArtifactKind::LinuxAppImage,
        "x86_64-unknown-linux-gnu",
        &path,
    )
    .unwrap();
    let range = SchemaRange {
        minimum: 1,
        maximum: 1,
    };
    let manifest = build_manifest(
        format!("0.{sequence}.0"),
        sequence,
        ReleaseChannel::Stable,
        false,
        vec![artifact],
        vec![StateCompatibility {
            state: "client_profiles".to_owned(),
            reads: range,
            writes: range,
        }],
    )
    .unwrap();
    let manifest = encode_manifest(&manifest).unwrap();
    let (private, public) = match private {
        Some((private, public)) => (private.to_owned(), public.to_owned()),
        None => {
            let (private, public) = generate_signing_keypair().unwrap();
            (private.to_string(), public)
        }
    };
    let signature = sign_manifest(&manifest, &private).unwrap();
    Release {
        manifest,
        signature,
        private,
        public,
    }
}

fn verify(notes: &[u8], release: &Release) -> Result<String, ReleaseError> {
    verify_release_notes(
        notes,
        &release.manifest,
        &release.signature,
        &release.public,
    )
}

/// Signs arbitrary fields directly, so verification is tested beyond what signing allows.
fn forged(release: &Release, edit: impl FnOnce(&mut ReleaseNotes)) -> Vec<u8> {
    let mut notes: ReleaseNotes = serde_json::from_slice(
        &sign_release_notes(&release.manifest, SUMMARY, &release.private).unwrap(),
    )
    .unwrap();
    edit(&mut notes);
    let key = SigningKey::from_pkcs8_pem(&release.private).unwrap();
    notes.signature = STANDARD.encode(key.sign(&notes_message(&notes)).to_bytes());
    canonical_json(&notes).unwrap()
}

#[test]
fn signed_notes_round_trip_directly_and_through_the_trust_policy() {
    let release = release(2, None);
    let notes = sign_release_notes(&release.manifest, SUMMARY, &release.private).unwrap();
    assert_eq!(verify(&notes, &release).unwrap(), SUMMARY);

    let (root_private, root) = generate_signing_keypair().unwrap();
    let policy =
        encode_trust_policy(&build_trust_policy(1, vec![release.public.clone()], vec![]).unwrap())
            .unwrap();
    let trust_signature = sign_trust_policy(&policy, &root_private).unwrap();
    let trust = verify_trust_policy(&policy, &trust_signature, &root).unwrap();
    assert_eq!(
        verify_release_notes_with_trust_policy(
            &notes,
            &release.manifest,
            &release.signature,
            &trust
        )
        .unwrap(),
        SUMMARY
    );
    let revoked = encode_trust_policy(
        &build_trust_policy(
            2,
            vec![generate_signing_keypair().unwrap().1],
            vec![crate::public_key_id(&release.public).unwrap()],
        )
        .unwrap(),
    )
    .unwrap();
    let revoked_signature = sign_trust_policy(&revoked, &root_private).unwrap();
    let revoked = verify_trust_policy(&revoked, &revoked_signature, &root).unwrap();
    assert!(matches!(
        verify_release_notes_with_trust_policy(
            &notes,
            &release.manifest,
            &release.signature,
            &revoked
        ),
        Err(ReleaseError::ReleaseKeyRevoked)
    ));
}

#[test]
fn tampered_or_wrongly_signed_notes_are_rejected() {
    let release = release(2, None);
    let notes = sign_release_notes(&release.manifest, SUMMARY, &release.private).unwrap();
    let mut tampered: ReleaseNotes = serde_json::from_slice(&notes).unwrap();
    tampered.summary = "Adds a feature this release does not have.".to_owned();
    assert!(matches!(
        verify(&canonical_json(&tampered).unwrap(), &release),
        Err(ReleaseError::ReleaseNotesMismatch)
    ));

    let (other_private, _) = generate_signing_keypair().unwrap();
    let other_key = sign_release_notes(&release.manifest, SUMMARY, &other_private).unwrap();
    assert!(matches!(
        verify(&other_key, &release),
        Err(ReleaseError::ReleaseNotesMismatch)
    ));

    let compact =
        serde_json::to_vec(&serde_json::from_slice::<ReleaseNotes>(&notes).unwrap()).unwrap();
    assert!(matches!(
        verify(&compact, &release),
        Err(ReleaseError::InvalidReleaseNotes)
    ));
    let mut unknown: serde_json::Value = serde_json::from_slice(&notes).unwrap();
    unknown["link"] = "example".into();
    assert!(matches!(
        verify(&canonical_json(&unknown).unwrap(), &release),
        Err(ReleaseError::InvalidReleaseNotes)
    ));
}

#[test]
fn notes_cannot_be_replayed_onto_another_manifest_or_sequence() {
    let first = release(2, None);
    let second = release(3, Some((&first.private, &first.public)));
    let notes = sign_release_notes(&first.manifest, SUMMARY, &first.private).unwrap();
    assert!(matches!(
        verify(&notes, &second),
        Err(ReleaseError::ReleaseNotesMismatch)
    ));
    let other_sequence = forged(&first, |notes| notes.release_sequence = 3);
    assert!(matches!(
        verify(&other_sequence, &first),
        Err(ReleaseError::ReleaseNotesMismatch)
    ));
    let other_digest = forged(&first, |notes| notes.manifest_sha256 = "a".repeat(64));
    assert!(matches!(
        verify(&other_digest, &first),
        Err(ReleaseError::ReleaseNotesMismatch)
    ));
}

#[test]
fn summaries_are_one_short_plain_text_line() {
    let release = release(2, None);
    let at_limit = "a".repeat(MAX_RELEASE_SUMMARY_CHARACTERS);
    assert!(sign_release_notes(&release.manifest, &at_limit, &release.private).is_ok());
    for summary in [
        "",
        " Leading space.",
        &"a".repeat(MAX_RELEASE_SUMMARY_CHARACTERS + 1),
        "Two\nlines.",
        "Tab\there.",
        "Bell\u{7}.",
        "<b>Bold</b> text.",
        "See ftp://updates.example for details.",
        "Right-to-left \u{202e}override.",
        "Zero\u{200b}width.",
    ] {
        assert!(
            matches!(
                sign_release_notes(&release.manifest, summary, &release.private),
                Err(ReleaseError::InvalidReleaseNotes)
            ),
            "{summary:?}"
        );
        // Verification applies the same rule to a correctly signed file.
        let signed = forged(&release, |notes| notes.summary = summary.to_owned());
        assert!(
            matches!(
                verify(&signed, &release),
                Err(ReleaseError::InvalidReleaseNotes)
            ),
            "{summary:?}"
        );
    }
    let oversized = vec![b' '; MAX_RELEASE_NOTES_BYTES as usize + 1];
    assert!(matches!(
        verify(&oversized, &release),
        Err(ReleaseError::InvalidReleaseNotes)
    ));
}
