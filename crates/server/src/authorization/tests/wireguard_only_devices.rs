use super::*;

fn add_wireguard_device(state: &mut AuthorizationDocument, member_id: MemberId) -> DeviceId {
    let id = DeviceId::new();
    let address = state.allocate_member_address().unwrap();
    state.devices.push(DeviceRecord {
        id,
        member_id,
        name: "Phone".into(),
        client_tunnel_address: address,
        wireguard_public_key: STANDARD.encode([9_u8; 32]),
        management_certificate_pem: String::new(),
        certificate_fingerprint: String::new(),
        peer_communication_enabled: false,
        preshared_key: Some(STANDARD.encode([8_u8; 32])),
        subnet_routes: Vec::new(),
    });
    state.schema_version = state.required_schema_version();
    id
}

#[test]
fn wireguard_only_devices_need_schema_seven_and_a_preshared_key() {
    let mut state = state();
    let (member_id, _) = add_member(&mut state, "Family", false);
    state.schema_version = state.required_schema_version();
    let fingerprint = state.endpoint_authorization_fingerprint().unwrap();
    let managed = serde_json::to_value(&state).unwrap();
    add_wireguard_device(&mut state, member_id);
    assert_eq!(
        state.schema_version,
        WIREGUARD_ONLY_AUTHORIZATION_SCHEMA_VERSION
    );
    state.validate().unwrap();
    // Managed devices serialize exactly as before, so older fingerprints stay stable.
    let stored = serde_json::to_value(&state).unwrap();
    assert_eq!(stored["devices"][1], managed["devices"][1]);
    assert!(
        stored["devices"][2]
            .get("management_certificate_pem")
            .is_none()
    );
    assert_ne!(
        state.endpoint_authorization_fingerprint().unwrap(),
        fingerprint
    );
    let reloaded: AuthorizationDocument =
        serde_json::from_slice(&serde_json::to_vec(&state).unwrap()).unwrap();
    assert_eq!(reloaded, state);

    let mut older = state.clone();
    older.schema_version = PRESHARED_KEY_AUTHORIZATION_SCHEMA_VERSION;
    assert!(older.validate().is_err());
    let mut keyless = state.clone();
    keyless.devices[2].preshared_key = None;
    assert!(keyless.validate().is_err());
    let mut half_certificate = state.clone();
    half_certificate.devices[2].certificate_fingerprint = "00".repeat(32);
    assert!(half_certificate.validate().is_err());
    let mut duplicate = state.clone();
    duplicate.devices[2].wireguard_public_key = duplicate.devices[1].wireguard_public_key.clone();
    assert!(duplicate.validate().is_err());

    let device_id = state.devices[2].id;
    state.remove_device_and_dependents(device_id, member_id);
    assert_eq!(state.schema_version, AUTHORIZATION_SCHEMA_VERSION);
    state.validate().unwrap();
}

#[test]
fn wireguard_only_devices_get_a_direct_peer_but_no_management_or_relay_identity() {
    let mut state = state();
    let (member_id, _) = add_member(&mut state, "Family", false);
    let certificates = state.client_certificates(1);
    let device_id = add_wireguard_device(&mut state, member_id);
    let device = state.devices[2].clone();
    let peer = state
        .desired_peers(1)
        .into_iter()
        .find(|peer| peer.public_key == device.wireguard_public_key)
        .unwrap();
    assert_eq!(peer.address, device.client_tunnel_address);
    assert_eq!(peer.preshared_key, device.preshared_key);
    assert_eq!(state.client_certificates(1), certificates);
    assert!(state.device_for_fingerprint("").is_none());
    let relay_peers = crate::decoded_transport_peers(&state).unwrap();
    assert_eq!(relay_peers.len(), 2);
    assert!(!relay_peers.contains(&[9_u8; 32]));
    let summary = &state.snapshot(1).members[1].devices;
    assert!(
        summary
            .iter()
            .any(|device| device.id == device_id && device.wireguard_only)
    );

    // Suspension removes its peer like any other device of the member.
    state.set_member_suspended(member_id, true).unwrap();
    assert!(
        state
            .desired_peers(1)
            .iter()
            .all(|peer| peer.public_key != device.wireguard_public_key)
    );
}

#[test]
fn ownership_never_moves_to_a_member_that_cannot_manage_the_server() {
    let mut state = state();
    let (member_id, _) = add_member(&mut state, "Family", false);
    let device_id = add_wireguard_device(&mut state, member_id);
    let before = state.clone();
    assert!(state.transfer_ownership(device_id).is_err());
    assert_eq!(state, before);
    let managed = state.devices[1].id;
    state.transfer_ownership(managed).unwrap();
}
