use super::*;
use crate::dns_blocklist::{settings_handler, update_handler};
use sirinvpn_protocol::DnsBlocklistPolicy;

#[tokio::test]
async fn blocklist_settings_are_manager_only_and_validated_before_any_change() {
    let (_directory, state) = fixture();
    let before = state.authorization.as_ref().unwrap().read().await.clone();
    let caller = |index: usize| Extension(identity(&before.devices[index]));
    // Devices: the Owner, the Admin, then ordinary Members.
    for (index, allowed) in [(0, true), (1, true), (2, false), (4, false)] {
        let read = settings_handler(State(state.clone()), caller(index)).await;
        let unchanged = update_handler(
            State(state.clone()),
            caller(index),
            Json(DnsBlocklistPolicy::default()),
        )
        .await;
        assert_eq!(read.is_ok(), allowed);
        assert_eq!(unchanged.is_ok(), allowed);
        if !allowed {
            assert_eq!(read.err().unwrap().status, StatusCode::FORBIDDEN);
            assert_eq!(unchanged.err().unwrap().status, StatusCode::FORBIDDEN);
        }
    }
    let settings = settings_handler(State(state.clone()), caller(1))
        .await
        .unwrap()
        .0
        .payload;
    assert_eq!(settings.presets.len(), 4);
    assert!(!settings.pending && !settings.policy.enabled);

    let member_change = update_handler(
        State(state.clone()),
        caller(2),
        Json(DnsBlocklistPolicy {
            enabled: true,
            sources: vec![settings.presets[0].url.clone()],
            allowlist: Vec::new(),
        }),
    )
    .await;
    assert_eq!(member_change.err().unwrap().status, StatusCode::FORBIDDEN);
    for invalid in [
        DnsBlocklistPolicy {
            enabled: true,
            ..Default::default()
        },
        DnsBlocklistPolicy {
            enabled: true,
            sources: vec!["http://lists.example/a.txt".into()],
            allowlist: Vec::new(),
        },
    ] {
        let result = update_handler(State(state.clone()), caller(0), Json(invalid)).await;
        assert_eq!(result.err().unwrap().status, StatusCode::BAD_REQUEST);
    }
    assert_eq!(*state.authorization.as_ref().unwrap().read().await, before);
}
