use super::*;
use crate::alerts::{settings_handler, test_handler, update_handler};
use sirinvpn_protocol::AlertPolicy;

#[tokio::test]
async fn alert_settings_are_owner_only_and_validated_before_any_change() {
    let (_directory, state) = fixture();
    let before = state.authorization.as_ref().unwrap().read().await.clone();
    let caller = |index: usize| Extension(identity(&before.devices[index]));
    // Devices: the Owner, the Admin, then ordinary Members.
    for (index, allowed) in [(0, true), (1, false), (2, false), (4, false)] {
        let read = settings_handler(State(state.clone()), caller(index)).await;
        let unchanged = update_handler(
            State(state.clone()),
            caller(index),
            Json(AlertPolicy::default()),
        )
        .await;
        assert_eq!(read.is_ok(), allowed);
        assert_eq!(unchanged.is_ok(), allowed);
        if !allowed {
            assert_eq!(read.err().unwrap().status, StatusCode::FORBIDDEN);
            assert_eq!(unchanged.err().unwrap().status, StatusCode::FORBIDDEN);
            let test = test_handler(State(state.clone()), caller(index)).await;
            assert_eq!(test.err().unwrap().status, StatusCode::FORBIDDEN);
        }
    }
    let test = test_handler(State(state.clone()), caller(0)).await;
    assert_eq!(test.err().unwrap().status, StatusCode::BAD_REQUEST);

    let invalid = AlertPolicy {
        alert_url: Some("https://10.77.0.5/topic".into()),
        ..Default::default()
    };
    let result = update_handler(State(state.clone()), caller(0), Json(invalid)).await;
    assert_eq!(result.err().unwrap().status, StatusCode::BAD_REQUEST);
    // This test host has no alert timer, as on a server installed before alerts existed.
    let valid = AlertPolicy {
        alert_url: Some("https://ntfy.example/topic".into()),
        ..Default::default()
    };
    let result = update_handler(State(state.clone()), caller(0), Json(valid)).await;
    assert_eq!(result.err().unwrap().status, StatusCode::CONFLICT);
    assert_eq!(*state.authorization.as_ref().unwrap().read().await, before);
}
