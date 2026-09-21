use super::*;
#[test]
fn release_commands_are_pinned_to_fixed_actions_and_quoted_sources() {
    let source = "https://releases.example/$(touch%20/tmp/unwanted)/";
    let command = action_arguments(&ServerReleaseAction::Check {
        source: source.into(),
        channel: "stable".into(),
    })
    .unwrap();
    assert!(command.contains("'https://releases.example/$(touch%20/tmp/unwanted)/'"));
    assert!(
        action_arguments(&ServerReleaseAction::Install {
            manifest_sha256: "x; rm".into()
        })
        .is_err()
    );
    assert!(action_arguments(&ServerReleaseAction::Rollback { confirmed: false }).is_err());
    assert!(
        action_arguments(&ServerReleaseAction::Check {
            source: "https://releases.example/?device=1".into(),
            channel: "stable".into()
        })
        .is_err()
    );
    assert!(
        parse_response("{\"error\":\"signature rejected\"}")
            .unwrap_err()
            .to_string()
            .contains("signature rejected")
    );
}
