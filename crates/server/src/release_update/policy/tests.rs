use super::*;

#[test]
fn security_schedule_requires_a_stable_security_release_above_the_high_watermark() {
    use sirinvpn_release::{
        InstalledReleaseSummary, ReleaseArtifact, SchemaRange, StateCompatibility,
    };
    let artifact = ReleaseArtifact {
        kind: ArtifactKind::ServerElf,
        target: "x86_64-unknown-linux-gnu".into(),
        file_name: "sirinvpn-server".into(),
        size_bytes: 1024,
        sha256: "a".repeat(64),
    };
    let mut installed = InstalledReleaseSummary {
        schema_version: 1,
        channel: ReleaseChannel::Stable,
        active_release_version: "1.0.0".into(),
        active_release_sequence: 10,
        active_manifest_sha256: "b".repeat(64),
        active_artifact: artifact.clone(),
        highest_accepted_release_version: "2.0.0".into(),
        highest_accepted_release_sequence: 12,
        highest_accepted_manifest_sha256: "c".repeat(64),
        key_id_sha256: "d".repeat(64),
    };
    let mut candidate = sirinvpn_release::build_manifest(
        "3.0.0",
        11,
        ReleaseChannel::Stable,
        true,
        vec![artifact],
        vec![StateCompatibility {
            state: "server_configuration".into(),
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
    assert!(!eligible_security_update(&installed, &candidate));
    candidate.release_sequence = 12;
    assert!(!eligible_security_update(&installed, &candidate));
    candidate.release_sequence = 13;
    assert!(eligible_security_update(&installed, &candidate));
    candidate.security_update = false;
    assert!(!eligible_security_update(&installed, &candidate));
    candidate.security_update = true;
    candidate.channel = ReleaseChannel::Preview;
    assert!(!eligible_security_update(&installed, &candidate));
    candidate.channel = ReleaseChannel::Stable;
    installed.channel = ReleaseChannel::Preview;
    assert!(!eligible_security_update(&installed, &candidate));
}
#[test]
fn automatic_updates_are_disabled_by_default_and_reject_private_url_fields() {
    let default = SecurityUpdatePolicy::default();
    assert!(!default.enabled);
    assert!(default.source.is_none());
    assert!(validate(&default).is_ok());
    for source in [
        None,
        Some("http://releases.example/"),
        Some("https://user:pass@releases.example/"),
        Some("https://releases.example/?device=private"),
        Some("https://releases.example/#private"),
    ] {
        assert!(
            validate(&SecurityUpdatePolicy {
                enabled: true,
                source: source.map(str::to_owned),
                ..default.clone()
            })
            .is_err()
        );
    }
    assert!(
        validate(&SecurityUpdatePolicy {
            enabled: true,
            source: Some("https://releases.example/stable/".to_owned()),
            ..default
        })
        .is_ok()
    );
}
