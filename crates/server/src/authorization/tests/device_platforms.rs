use super::*;

#[test]
fn a_platform_keeps_the_schema_and_the_endpoint_binding() {
    let mut state = state();
    add_member(&mut state, "Family", false);
    let schema = state.required_schema_version();
    let earlier = serde_json::to_value(&state).unwrap();
    let fingerprint = state.endpoint_authorization_fingerprint().unwrap();
    state.devices[1].platform = Some("android".into());
    // Display only: no schema move, so a rolled-back VPS still loads and simply drops it.
    assert_eq!(state.required_schema_version(), schema);
    assert_eq!(
        state.endpoint_authorization_fingerprint().unwrap(),
        fingerprint
    );
    let stored = serde_json::to_value(&state).unwrap();
    assert_eq!(stored["devices"][0], earlier["devices"][0]);
    assert_eq!(stored["devices"][1]["platform"], "android");
    assert_eq!(
        serde_json::from_value::<AuthorizationDocument>(stored.clone()).unwrap(),
        state
    );
    // Device records tolerate fields they don't know, as the older readers do.
    let mut newer = stored;
    newer["devices"][1]["platform"] = "macos".into();
    newer["devices"][1]["future_field"] = true.into();
    serde_json::from_value::<AuthorizationDocument>(newer)
        .unwrap()
        .validate()
        .unwrap();
}
