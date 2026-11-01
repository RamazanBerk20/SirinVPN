use super::subnet_routes::{add_owner_device, device};
use super::*;

fn pair(device_id: DeviceId, peer_device_id: DeviceId, one_way: bool) -> DevicePair {
    DevicePair {
        device_id,
        peer_device_id,
        one_way,
    }
}

#[test]
fn device_pairs_need_schema_nine_known_devices_and_one_pair_per_two_devices() {
    let mut state = state();
    add_member(&mut state, "Family", false);
    add_member(&mut state, "Other", false);
    let (owner, family, other) = (
        state.devices[0].id,
        state.devices[1].id,
        state.devices[2].id,
    );
    state.schema_version = state.required_schema_version();
    let earlier_schema = state.schema_version;
    let earlier = serde_json::to_value(&state).unwrap();

    state.set_device_pair(pair(owner, family, false)).unwrap();
    assert_eq!(
        state.schema_version,
        DEVICE_PAIR_AUTHORIZATION_SCHEMA_VERSION
    );
    let reloaded: AuthorizationDocument =
        serde_json::from_slice(&serde_json::to_vec(&state).unwrap()).unwrap();
    assert_eq!(reloaded, state);
    // A schema-8 reader would drop the pair and silently isolate both devices.
    let mut older = state.clone();
    older.schema_version = SUBNET_ROUTE_AUTHORIZATION_SCHEMA_VERSION;
    assert!(older.validate().is_err());

    // The same two devices hold one pair; setting it again in either order replaces it.
    state.set_device_pair(pair(family, owner, true)).unwrap();
    assert_eq!(state.device_pairs, [pair(family, owner, true)]);
    for invalid in [
        pair(owner, owner, false),
        pair(owner, DeviceId::new(), false),
    ] {
        assert!(state.clone().set_device_pair(invalid).is_err());
    }
    let mut duplicated = state.clone();
    duplicated.device_pairs.push(pair(owner, family, false));
    assert!(duplicated.validate().is_err());
    state.set_device_pair(pair(other, family, false)).unwrap();

    // Each stored pair is checked again on load, up to the server-wide bound.
    let member_id = state.devices[0].member_id;
    for index in 0..23_u8 {
        state.devices.push(DeviceRecord {
            id: DeviceId::new(),
            member_id,
            name: format!("Phone {index}"),
            client_tunnel_address: state.allocate_member_address().unwrap(),
            wireguard_public_key: STANDARD.encode([index + 1; 32]),
            management_certificate_pem: String::new(),
            certificate_fingerprint: String::new(),
            peer_communication_enabled: false,
            preshared_key: Some(STANDARD.encode([index + 1; 32])),
            subnet_routes: Vec::new(),
        });
    }
    let ids: Vec<_> = state.devices.iter().map(|device| device.id).collect();
    let mut full = state.clone();
    full.device_pairs = ids
        .iter()
        .enumerate()
        .flat_map(|(index, id)| ids[index + 1..].iter().map(|peer| pair(*id, *peer, false)))
        .take(MAX_DEVICE_PAIRS + 1)
        .collect();
    assert!(full.validate().is_err());
    full.device_pairs.pop();
    full.validate().unwrap();

    state.devices.truncate(3);
    state.remove_device_pair(owner, family).unwrap();
    state.remove_device_pair(family, other).unwrap();
    assert_eq!(state.schema_version, earlier_schema);
    assert_eq!(serde_json::to_value(&state).unwrap(), earlier);
}

#[test]
fn pairs_reach_by_direction_open_router_networks_and_follow_the_lifecycle() {
    let mut state = state();
    let (family_member, _) = add_member(&mut state, "Family", false);
    let (other_member, _) = add_member(&mut state, "Other", false);
    let (owner, family, other) = (
        state.devices[0].id,
        state.devices[1].id,
        state.devices[2].id,
    );
    let router = add_owner_device(&mut state);
    state.devices[3].peer_communication_enabled = false;
    state
        .set_device_subnet_routes(router, vec!["192.168.1.0/24".into()])
        .unwrap();
    let announced = vec!["192.168.1.0/24".to_owned()];
    let reachable =
        |state: &AuthorizationDocument, id| state.reachable_subnet_routes(device(state, id));
    let live =
        |state: &AuthorizationDocument| state.live_subnet_routes(device(state, router)).to_vec();
    assert!(live(&state).is_empty());

    // Family may start connections to the router, and so reaches its network; the router
    // and its network only answer.
    state.set_device_pair(pair(family, router, true)).unwrap();
    assert!(state.pair_permits(device(&state, family), device(&state, router)));
    assert!(!state.pair_permits(device(&state, router), device(&state, family)));
    assert_eq!(live(&state), announced);
    assert_eq!(reachable(&state, family), announced);
    assert!(reachable(&state, router).is_empty());
    // A pair the router starts opens nothing behind it.
    state.set_device_pair(pair(router, other, true)).unwrap();
    assert!(reachable(&state, other).is_empty());
    // The switch reaches only routers that have it on too.
    state.set_device_peer_communication(owner, true).unwrap();
    assert!(reachable(&state, owner).is_empty());
    state.set_device_peer_communication(router, true).unwrap();
    assert_eq!(reachable(&state, owner), announced);
    state.set_device_peer_communication(router, false).unwrap();

    // Suspension keeps the pair but makes it inactive until reactivation.
    state.set_member_suspended(family_member, true).unwrap();
    assert!(!state.pair_permits(device(&state, family), device(&state, router)));
    assert!(live(&state).is_empty());
    assert!(reachable(&state, family).is_empty());
    state.set_member_suspended(family_member, false).unwrap();
    assert_eq!(reachable(&state, family), announced);

    // Pairs are server policy like the switch: they survive ownership transfer, while the
    // earlier Owner's networks close.
    let mut transferred = state.clone();
    transferred.transfer_ownership(family).unwrap();
    assert_eq!(transferred.device_pairs, state.device_pairs);
    assert!(reachable(&transferred, family).is_empty());

    // Revoking a device or a member removes their pairs; the schema returns to the routes'.
    state.remove_device_and_dependents(family, family_member);
    state.validate().unwrap();
    assert_eq!(state.device_pairs, [pair(router, other, true)]);
    state.revoke_member_devices(other_member).unwrap();
    assert!(state.device_pairs.is_empty());
    assert_eq!(
        state.schema_version,
        SUBNET_ROUTE_AUTHORIZATION_SCHEMA_VERSION
    );
}
