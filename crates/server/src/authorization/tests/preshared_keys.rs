use super::*;

fn key(byte: u8) -> String {
    STANDARD.encode([byte; 32])
}

fn rotation(
    state: &AuthorizationDocument,
    replacement: &LocalIdentity,
    preshared_key: Option<String>,
) -> KeyRotationPrepareRequest {
    KeyRotationPrepareRequest {
        rotation_id: KeyRotationId::new(),
        server_id: state.server_id,
        new_wireguard_public_key: replacement.public.wireguard_public_key.clone(),
        new_management_certificate_pem: replacement.public.management_certificate_pem.clone(),
        new_wireguard_preshared_key: preshared_key,
    }
}

#[test]
fn preshared_keys_require_schema_six_and_stay_out_of_endpoint_bindings() {
    let mut state = state();
    let legacy = serde_json::to_value(&state).unwrap();
    assert!(legacy["devices"][0].get("preshared_key").is_none());
    let fingerprint = state.endpoint_authorization_fingerprint().unwrap();

    state.devices[0].preshared_key = Some(key(1));
    // Readers before schema 6 would load the document and silently drop the key.
    assert!(state.validate().is_err());
    state.schema_version = state.required_schema_version();
    assert_eq!(
        state.schema_version,
        PRESHARED_KEY_AUTHORIZATION_SCHEMA_VERSION
    );
    state.validate().unwrap();
    assert_eq!(
        state.endpoint_authorization_fingerprint().unwrap(),
        fingerprint
    );
    let reloaded: AuthorizationDocument =
        serde_json::from_slice(&serde_json::to_vec(&state).unwrap()).unwrap();
    assert_eq!(reloaded, state);

    let peers = state.desired_peers(1);
    assert_eq!(peers[0].public_key, state.devices[0].wireguard_public_key);
    assert_eq!(peers[0].preshared_key, Some(key(1)));

    for invalid in [
        "not base64".to_owned(),
        STANDARD.encode([1_u8; 31]),
        base64::engine::general_purpose::STANDARD_NO_PAD.encode([1_u8; 32]),
    ] {
        let mut malformed = state.clone();
        malformed.devices[0].preshared_key = Some(invalid);
        assert!(malformed.validate().is_err());
    }

    state.devices[0].preshared_key = None;
    state.schema_version = state.required_schema_version();
    assert_eq!(state.schema_version, AUTHORIZATION_SCHEMA_VERSION);
    state.validate().unwrap();
}

#[test]
fn rotation_installs_the_offered_key_and_a_keyless_rotation_removes_the_old_one() {
    let mut state = state();
    state.devices[0].preshared_key = Some(key(1));
    state.schema_version = state.required_schema_version();
    let original = state.devices[0].clone();
    let replacement = LocalIdentity::generate("Rotated with key").unwrap();
    let request = rotation(&state, &replacement, Some(key(2)));
    state
        .prepare_key_rotation(&original.certificate_fingerprint, &request, 10)
        .unwrap();
    assert_eq!(state.key_rotations[0].new_preshared_key, Some(key(2)));
    // Until commit the device keeps its original peer and key.
    let peer = state
        .desired_peers(11)
        .into_iter()
        .find(|peer| peer.public_key == original.wireguard_public_key)
        .unwrap();
    assert_eq!(peer.preshared_key, Some(key(1)));
    let mut retried_with_other_key = request.clone();
    retried_with_other_key.new_wireguard_preshared_key = Some(key(3));
    assert!(
        state
            .prepare_key_rotation(
                &original.certificate_fingerprint,
                &retried_with_other_key,
                11
            )
            .is_err()
    );
    state
        .prepare_key_rotation(&original.certificate_fingerprint, &request, 11)
        .unwrap();

    let new_fingerprint =
        certificate_fingerprint(&replacement.public.management_certificate_pem).unwrap();
    state
        .commit_key_rotation(request.rotation_id, &new_fingerprint, 12)
        .unwrap();
    assert_eq!(state.devices[0].preshared_key, Some(key(2)));
    assert_eq!(
        state.schema_version,
        PRESHARED_KEY_AUTHORIZATION_SCHEMA_VERSION
    );
    state.validate().unwrap();

    // An older client offers no key; its new peer must not inherit the previous one.
    let keyless = LocalIdentity::generate("Rotated without key").unwrap();
    let request = rotation(&state, &keyless, None);
    state
        .prepare_key_rotation(&new_fingerprint, &request, 20)
        .unwrap();
    let keyless_fingerprint =
        certificate_fingerprint(&keyless.public.management_certificate_pem).unwrap();
    state
        .commit_key_rotation(request.rotation_id, &keyless_fingerprint, 21)
        .unwrap();
    assert_eq!(state.devices[0].preshared_key, None);
    assert_eq!(state.schema_version, AUTHORIZATION_SCHEMA_VERSION);
    state.validate().unwrap();

    let another = LocalIdentity::generate("Malformed key").unwrap();
    let malformed = rotation(&state, &another, Some("short".into()));
    assert!(
        state
            .prepare_key_rotation(&keyless_fingerprint, &malformed, 30)
            .is_err()
    );
    assert!(state.key_rotations.is_empty());
}

#[test]
fn cancelling_a_keyed_rotation_restores_the_previous_schema() {
    let mut state = state();
    let original = state.devices[0].clone();
    let replacement = LocalIdentity::generate("Cancelled").unwrap();
    let request = rotation(&state, &replacement, Some(key(5)));
    state
        .prepare_key_rotation(&original.certificate_fingerprint, &request, 10)
        .unwrap();
    assert_eq!(
        state.schema_version,
        PRESHARED_KEY_AUTHORIZATION_SCHEMA_VERSION
    );
    state
        .cancel_key_rotation(request.rotation_id, &original.certificate_fingerprint)
        .unwrap();
    assert!(state.key_rotations.is_empty());
    assert_eq!(state.schema_version, AUTHORIZATION_SCHEMA_VERSION);
    state.validate().unwrap();

    state
        .prepare_key_rotation(&original.certificate_fingerprint, &request, 20)
        .unwrap();
    assert!(state.prune_expired(20 + KEY_ROTATION_LIFETIME_SECONDS));
    assert_eq!(state.schema_version, AUTHORIZATION_SCHEMA_VERSION);
    state.validate().unwrap();
}
