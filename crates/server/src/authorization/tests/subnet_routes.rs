use super::*;
use sirinvpn_protocol::MAX_SUBNET_ROUTES;

fn add_owner_device(state: &mut AuthorizationDocument) -> DeviceId {
    let identity = LocalIdentity::generate("Home").unwrap();
    let id = DeviceId::new();
    let address = state.allocate_member_address().unwrap();
    state.devices.push(DeviceRecord {
        id,
        member_id: state.devices[0].member_id,
        name: "Home server".into(),
        client_tunnel_address: address,
        wireguard_public_key: identity.public.wireguard_public_key,
        certificate_fingerprint: certificate_fingerprint(
            &identity.public.management_certificate_pem,
        )
        .unwrap(),
        management_certificate_pem: identity.public.management_certificate_pem,
        peer_communication_enabled: true,
        preshared_key: None,
        subnet_routes: Vec::new(),
    });
    id
}

fn device(state: &AuthorizationDocument, id: DeviceId) -> &DeviceRecord {
    state.devices.iter().find(|device| device.id == id).unwrap()
}

#[test]
fn subnet_routes_need_schema_eight_owner_devices_and_distinct_ranges() {
    let mut state = state();
    add_member(&mut state, "Family", false);
    let family = state.devices[1].id;
    let router = add_owner_device(&mut state);
    let laptop = add_owner_device(&mut state);
    state.schema_version = state.required_schema_version();
    let earlier_schema = state.schema_version;
    let earlier = serde_json::to_value(&state).unwrap();

    state
        .set_device_subnet_routes(router, vec!["192.168.1.0/24".into()])
        .unwrap();
    assert_eq!(
        state.schema_version,
        SUBNET_ROUTE_AUTHORIZATION_SCHEMA_VERSION
    );
    // Devices without routes serialize exactly as before.
    let stored = serde_json::to_value(&state).unwrap();
    assert_eq!(stored["devices"][1], earlier["devices"][1]);
    assert_eq!(
        stored["devices"][2]["subnet_routes"],
        serde_json::json!(["192.168.1.0/24"])
    );
    let reloaded: AuthorizationDocument =
        serde_json::from_slice(&serde_json::to_vec(&state).unwrap()).unwrap();
    assert_eq!(reloaded, state);
    let mut older = state.clone();
    older.schema_version = WIREGUARD_ONLY_AUTHORIZATION_SCHEMA_VERSION;
    assert!(older.validate().is_err());

    for (target, routes) in [
        (laptop, vec!["192.168.1.128/25"]),
        (laptop, vec!["192.168.0.0/16"]),
        (router, vec!["192.168.1.0/24", "192.168.1.0/24"]),
        (router, vec!["10.77.0.0/24"]),
        (router, vec!["10.77.1.0/24"]),
        (router, vec!["0.0.0.0/0"]),
        (router, vec!["192.168.1.1/24"]),
        (family, vec!["192.168.9.0/24"]),
    ] {
        let mut next = state.clone();
        let routes = routes.into_iter().map(str::to_owned).collect();
        assert!(
            next.set_device_subnet_routes(target, routes).is_err(),
            "{target:?}"
        );
    }
    let mut next = state.clone();
    let routes: Vec<_> = (2..=MAX_SUBNET_ROUTES)
        .map(|index| format!("10.{index}.0.0/16"))
        .collect();
    next.set_device_subnet_routes(laptop, routes.clone())
        .unwrap();
    let mut too_many = routes;
    too_many.push("10.200.0.0/16".into());
    assert!(next.set_device_subnet_routes(laptop, too_many).is_err());

    state.set_device_subnet_routes(router, Vec::new()).unwrap();
    assert_eq!(state.schema_version, earlier_schema);
    assert_eq!(serde_json::to_value(&state).unwrap(), earlier);
}

#[test]
fn only_live_routes_reach_wireguard_and_peer_enabled_devices() {
    let mut state = state();
    add_member(&mut state, "Family", false);
    let family = state.devices[1].id;
    let router = add_owner_device(&mut state);
    state
        .set_device_subnet_routes(router, vec!["192.168.1.0/24".into()])
        .unwrap();
    let routes_of = |state: &AuthorizationDocument, id: DeviceId| {
        let key = &device(state, id).wireguard_public_key;
        state
            .desired_peers(crate::unix_time())
            .into_iter()
            .find(|peer| &peer.public_key == key)
            .unwrap()
            .subnet_routes
    };
    let announced = vec!["192.168.1.0/24".to_owned()];
    assert_eq!(routes_of(&state, router), announced);
    // The family device has no peer permission yet.
    assert!(
        state
            .reachable_subnet_routes(device(&state, family))
            .is_empty()
    );
    state.set_device_peer_communication(family, true).unwrap();
    assert_eq!(
        state.reachable_subnet_routes(device(&state, family)),
        announced
    );
    assert!(
        state
            .reachable_subnet_routes(device(&state, router))
            .is_empty()
    );
    // Suspension and schedules make the consumer unreachable through the same access check.
    let family_member = device(&state, family).member_id;
    state.set_member_suspended(family_member, true).unwrap();
    assert!(
        state
            .reachable_subnet_routes(device(&state, family))
            .is_empty()
    );
    state.set_member_suspended(family_member, false).unwrap();

    // Without peer permission the router announces nothing anywhere.
    state.set_device_peer_communication(router, false).unwrap();
    assert!(routes_of(&state, router).is_empty());
    assert!(state.live_subnet_routes(device(&state, router)).is_empty());
    assert!(
        state
            .reachable_subnet_routes(device(&state, family))
            .is_empty()
    );
    state.set_device_peer_communication(router, true).unwrap();

    // Ownership moves: the earlier owner's networks are closed for the new owner to decide.
    let mut transferred = state.clone();
    transferred.transfer_ownership(family).unwrap();
    assert!(
        transferred
            .devices
            .iter()
            .all(|device| device.subnet_routes.is_empty())
    );
    transferred.validate().unwrap();

    // Revocation removes the record, and the routes with it.
    let owner = device(&state, router).member_id;
    state.remove_device_and_dependents(router, owner);
    state.validate().unwrap();
    assert!(
        state
            .reachable_subnet_routes(device(&state, family))
            .is_empty()
    );
    assert!(
        state
            .desired_peers(crate::unix_time())
            .iter()
            .all(|peer| peer.subnet_routes.is_empty())
    );
}
