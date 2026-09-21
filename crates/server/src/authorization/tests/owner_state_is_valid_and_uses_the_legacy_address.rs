use super::*;

#[test]
fn owner_state_is_valid_and_uses_the_legacy_address() {
    let state = state();
    assert!(state.validate().is_ok());
    assert_eq!(
        state.devices[0].client_tunnel_address,
        "10.77.0.2".parse::<IpAddr>().unwrap()
    );
    assert!(!state.devices[0].peer_communication_enabled);
    assert!(
        serde_json::to_value(&state).unwrap()["devices"][0]
            .get("peer_communication_enabled")
            .is_none()
    );
}

#[test]
fn peer_communication_is_explicit_and_device_scoped() {
    let mut state = state();
    let (_, _) = add_member(&mut state, "Alice", false);
    let owner_id = state.devices[0].id;
    let member_id = state.devices[1].id;

    state.set_device_peer_communication(owner_id, true).unwrap();
    assert!(state.devices[0].peer_communication_enabled);
    assert!(!state.devices[1].peer_communication_enabled);
    let snapshot = state.snapshot(0);
    assert!(
        snapshot
            .members
            .iter()
            .flat_map(|member| &member.devices)
            .find(|device| device.id == owner_id)
            .unwrap()
            .peer_communication_enabled
    );
    assert!(
        serde_json::to_value(&state).unwrap()["devices"][0]
            .get("peer_communication_enabled")
            .is_some()
    );

    state
        .set_device_peer_communication(member_id, true)
        .unwrap();
    assert!(state.devices[1].peer_communication_enabled);
    assert!(
        state
            .set_device_peer_communication(DeviceId::new(), true)
            .is_err()
    );
}

#[test]
fn port_forwards_are_bounded_unique_and_follow_the_device_lifecycle() {
    let mut state = state();
    let (member_id, _) = add_member(&mut state, "Alice", false);
    let device_id = state.devices[1].id;
    let tcp = PortForward {
        protocol: PortForwardProtocol::Tcp,
        public_port: 48_080,
        device_id,
        device_port: 8_080,
    };
    state.add_port_forward(tcp.clone()).unwrap();
    state
        .add_port_forward(PortForward {
            protocol: PortForwardProtocol::Udp,
            ..tcp.clone()
        })
        .unwrap();
    assert_eq!(state.snapshot(0).port_forwards.len(), 2);
    assert!(state.add_port_forward(tcp.clone()).is_err());
    assert!(
        state
            .add_port_forward(PortForward {
                public_port: MIN_PORT_FORWARD_PUBLIC_PORT - 1,
                ..tcp.clone()
            })
            .is_err()
    );

    state
        .remove_port_forward(PortForwardProtocol::Tcp, tcp.public_port)
        .unwrap();
    assert_eq!(state.port_forwards.len(), 1);
    assert!(
        state
            .remove_port_forward(PortForwardProtocol::Tcp, tcp.public_port)
            .is_err()
    );
    state.remove_device_and_dependents(device_id, member_id);
    assert!(state.port_forwards.is_empty());
    assert!(state.validate().is_ok());
}

#[test]
fn endpoint_transition_is_additive_monotonic_state_with_verified_signature() {
    let mut state = state();
    let server = LocalIdentity::generate("Transition signing server").unwrap();
    let authorization_fingerprint = state.endpoint_authorization_fingerprint().unwrap();
    let claims = EndpointTransitionClaims {
        endpoint_discovery_port: None,
        alternate_endpoint_hosts: Vec::new(),
        previous_transports: None,
        schema_version: 1,
        server_id: state.server_id,
        generation: 1,
        server_name: "Migrated server".to_owned(),
        previous_endpoint: ServerEndpoint {
            host: "203.0.113.10".to_owned(),
            wireguard_port: 51_820,
        },
        endpoint: ServerEndpoint {
            host: "203.0.113.20".to_owned(),
            wireguard_port: 51_820,
        },
        server_tunnel_address: "10.77.0.1".parse().unwrap(),
        management_port: DEFAULT_MANAGEMENT_PORT,
        server_wireguard_public_key: server.public.wireguard_public_key,
        pinned_server_certificate_pem: server.public.management_certificate_pem,
        authorization_fingerprint,
        ipv6_tunnel_enabled: false,
        obfuscated_udp: None,
        tcp_fallback: None,
        tls_like: None,
    };
    let signing_key =
        SigningKey::from_pkcs8_pem(&server.secret.management_private_key_pem).unwrap();
    let signature = STANDARD.encode(
        signing_key
            .sign(&serde_json::to_vec(&claims).unwrap())
            .to_bytes(),
    );
    let response = EndpointTransitionResponse { claims, signature };
    state.accept_endpoint_transition(response.clone()).unwrap();
    state.validate().unwrap();
    assert_eq!(state.endpoint_generation(), 1);
    verify_endpoint_transition_signature_with_key(
        &server.secret.management_private_key_pem,
        state.endpoint_transition.as_ref().unwrap(),
    )
    .unwrap();

    let mut divergent_authorization = state.clone();
    divergent_authorization.members[0].name = "Changed owner".to_owned();
    divergent_authorization.validate().unwrap();
    divergent_authorization.endpoint_transition_source = true;
    assert!(divergent_authorization.validate().is_err());

    let mut handoff_source = state.clone();
    handoff_source.endpoint_transition_source = true;
    handoff_source.validate().unwrap();
    let mut invalid_source = state.clone();
    invalid_source.endpoint_transition = None;
    invalid_source.endpoint_transition_source = true;
    assert!(invalid_source.validate().is_err());

    let idempotent = state.clone();
    state.accept_endpoint_transition(response.clone()).unwrap();
    assert_eq!(state, idempotent);

    let mut generation_conflict = response.clone();
    generation_conflict.claims.endpoint.host = "203.0.113.21".to_owned();
    assert!(
        state
            .accept_endpoint_transition(generation_conflict)
            .is_err()
    );

    let mut broken_chain = response.clone();
    broken_chain.claims.generation = 2;
    broken_chain.claims.previous_endpoint.host = "203.0.113.88".to_owned();
    assert!(state.accept_endpoint_transition(broken_chain).is_err());

    let mut skipped_generation = response.clone();
    skipped_generation.claims.generation = 3;
    skipped_generation.claims.previous_endpoint = response.claims.endpoint.clone();
    skipped_generation.claims.endpoint.host = "203.0.113.30".to_owned();
    assert!(
        state
            .accept_endpoint_transition(skipped_generation)
            .is_err()
    );

    let mut tampered = state.endpoint_transition.clone().unwrap();
    tampered.claims.endpoint.host = "203.0.113.99".to_owned();
    assert!(
        verify_endpoint_transition_signature_with_key(
            &server.secret.management_private_key_pem,
            &tampered,
        )
        .is_err()
    );

    let mut legacy = serde_json::to_value(&state).unwrap();
    legacy
        .as_object_mut()
        .unwrap()
        .remove("endpoint_transition");
    let legacy: AuthorizationDocument = serde_json::from_value(legacy).unwrap();
    legacy.validate().unwrap();
    assert_eq!(legacy.endpoint_generation(), 0);
    assert!(!legacy.endpoint_transition_source);
}

#[test]
fn address_pools_do_not_overlap() {
    let state = state();
    assert_eq!(
        state.allocate_member_address().unwrap(),
        "10.77.0.3".parse::<IpAddr>().unwrap()
    );
    assert_eq!(
        state.allocate_bootstrap_address().unwrap(),
        "10.77.0.224".parse::<IpAddr>().unwrap()
    );
}

#[test]
fn authorization_writes_are_round_trippable() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("authorization.json");
    let state = state();
    write_authorization(&path, &state).unwrap();
    assert_eq!(load_authorization(&path).unwrap(), state);
    assert_eq!(
        fs::metadata(path).unwrap().permissions().mode() & 0o777,
        0o600
    );
}

#[test]
fn current_device_key_rotation_is_staged_idempotently_then_committed() {
    let mut state = state();
    state.devices[0].peer_communication_enabled = true;
    let original = state.devices[0].clone();
    let replacement = LocalIdentity::generate("Rotated owner").unwrap();
    let request = KeyRotationPrepareRequest {
        rotation_id: KeyRotationId::new(),
        server_id: state.server_id,
        new_wireguard_public_key: replacement.public.wireguard_public_key.clone(),
        new_management_certificate_pem: replacement.public.management_certificate_pem.clone(),
    };

    let prepared = state
        .prepare_key_rotation(&original.certificate_fingerprint, &request, 1_000)
        .unwrap();
    assert_eq!(prepared.rotation_id, request.rotation_id);
    assert_eq!(
        prepared.expires_at_unix,
        1_000 + KEY_ROTATION_LIFETIME_SECONDS
    );
    assert_eq!(state.key_rotations.len(), 1);
    assert_eq!(
        state
            .prepare_key_rotation(&original.certificate_fingerprint, &request, 1_001)
            .unwrap(),
        prepared
    );
    let trusted = state.client_certificates(1_001);
    assert!(trusted.contains(&original.management_certificate_pem));
    assert!(trusted.contains(&replacement.public.management_certificate_pem));
    let peers = state.desired_peers(1_001);
    assert!(
        peers
            .iter()
            .any(|peer| peer.public_key == original.wireguard_public_key)
    );
    assert!(
        !peers
            .iter()
            .any(|peer| peer.public_key == replacement.public.wireguard_public_key)
    );

    let replacement_fingerprint =
        certificate_fingerprint(&replacement.public.management_certificate_pem).unwrap();
    let committed = state
        .commit_key_rotation(request.rotation_id, &replacement_fingerprint, 1_002)
        .unwrap();
    assert_eq!(committed.server_id, state.server_id);
    assert_eq!(committed.device_id, original.id);
    assert_eq!(committed.identity_fingerprint, replacement_fingerprint);
    assert!(state.key_rotations.is_empty());
    let rotated = &state.devices[0];
    assert_eq!(rotated.id, original.id);
    assert_eq!(rotated.member_id, original.member_id);
    assert_eq!(rotated.name, original.name);
    assert_eq!(
        rotated.client_tunnel_address,
        original.client_tunnel_address
    );
    assert_eq!(
        rotated.wireguard_public_key,
        replacement.public.wireguard_public_key
    );
    assert_eq!(
        rotated.management_certificate_pem,
        replacement.public.management_certificate_pem
    );
    assert!(rotated.peer_communication_enabled);
    let trusted = state.client_certificates(1_003);
    assert!(!trusted.contains(&original.management_certificate_pem));
    assert!(trusted.contains(&rotated.management_certificate_pem));
    let peers = state.desired_peers(1_003);
    assert!(
        !peers
            .iter()
            .any(|peer| peer.public_key == original.wireguard_public_key)
    );
    assert!(
        peers
            .iter()
            .any(|peer| peer.public_key == rotated.wireguard_public_key)
    );
    state.validate().unwrap();
}

#[test]
fn expired_or_cancelled_rotation_keeps_the_original_device_identity() {
    let mut state = state();
    let original = state.devices[0].clone();
    let replacement = LocalIdentity::generate("Replacement").unwrap();
    let mut request = KeyRotationPrepareRequest {
        rotation_id: KeyRotationId::new(),
        server_id: state.server_id,
        new_wireguard_public_key: replacement.public.wireguard_public_key.clone(),
        new_management_certificate_pem: replacement.public.management_certificate_pem.clone(),
    };
    state
        .prepare_key_rotation(&original.certificate_fingerprint, &request, 5)
        .unwrap();
    assert!(state.prune_expired(5 + KEY_ROTATION_LIFETIME_SECONDS));
    assert!(state.key_rotations.is_empty());
    assert_eq!(state.devices[0], original);

    request.rotation_id = KeyRotationId::new();
    state
        .prepare_key_rotation(&original.certificate_fingerprint, &request, 10_000)
        .unwrap();
    assert!(
        state
            .cancel_key_rotation(request.rotation_id, "unauthorized")
            .is_err()
    );
    state
        .cancel_key_rotation(request.rotation_id, &original.certificate_fingerprint)
        .unwrap();
    assert!(state.key_rotations.is_empty());
    assert_eq!(state.devices[0], original);
}

#[test]
fn key_rotation_rejects_reused_identity_material_and_wrong_commit_certificate() {
    let mut state = state();
    let original = state.devices[0].clone();
    let reused = KeyRotationPrepareRequest {
        rotation_id: KeyRotationId::new(),
        server_id: state.server_id,
        new_wireguard_public_key: original.wireguard_public_key.clone(),
        new_management_certificate_pem: original.management_certificate_pem.clone(),
    };
    assert!(
        state
            .prepare_key_rotation(&original.certificate_fingerprint, &reused, 10)
            .is_err()
    );
    assert!(state.key_rotations.is_empty());

    let replacement = LocalIdentity::generate("Replacement").unwrap();
    let request = KeyRotationPrepareRequest {
        rotation_id: KeyRotationId::new(),
        server_id: state.server_id,
        new_wireguard_public_key: replacement.public.wireguard_public_key,
        new_management_certificate_pem: replacement.public.management_certificate_pem,
    };
    state
        .prepare_key_rotation(&original.certificate_fingerprint, &request, 10)
        .unwrap();
    assert!(
        state
            .commit_key_rotation(request.rotation_id, &original.certificate_fingerprint, 11)
            .is_err()
    );
    assert_eq!(state.devices[0], original);
    assert_eq!(state.key_rotations.len(), 1);
}

#[test]
fn administrator_state_and_additional_devices_are_legacy_reader_compatible() {
    #[derive(Deserialize)]
    struct LegacyAuthorizationDocument {
        schema_version: u16,
        server_id: ServerId,
        members: Vec<LegacyMemberRecord>,
        devices: Vec<DeviceRecord>,
        invitations: Vec<serde_json::Value>,
        enrollment_receipts: Vec<serde_json::Value>,
    }

    #[derive(Deserialize)]
    struct LegacyMemberRecord {
        id: MemberId,
        name: String,
        role: ServerRole,
    }

    let mut state = state();
    let (member_id, _) = add_member(&mut state, "Alice", true);
    let additional = LocalIdentity::generate("Alice tablet").unwrap();
    state.devices.push(DeviceRecord {
        id: DeviceId::new(),
        member_id,
        name: "Tablet".to_owned(),
        client_tunnel_address: state.allocate_member_address().unwrap(),
        wireguard_public_key: additional.public.wireguard_public_key,
        management_certificate_pem: additional.public.management_certificate_pem.clone(),
        certificate_fingerprint: certificate_fingerprint(
            &additional.public.management_certificate_pem,
        )
        .unwrap(),
        peer_communication_enabled: false,
    });
    let owner = state.devices[0].clone();
    let replacement = LocalIdentity::generate("Pending owner replacement").unwrap();
    state
        .prepare_key_rotation(
            &owner.certificate_fingerprint,
            &KeyRotationPrepareRequest {
                rotation_id: KeyRotationId::new(),
                server_id: state.server_id,
                new_wireguard_public_key: replacement.public.wireguard_public_key,
                new_management_certificate_pem: replacement.public.management_certificate_pem,
            },
            10,
        )
        .unwrap();
    state.validate().unwrap();

    let bytes = serde_json::to_vec(&state).unwrap();
    let legacy: LegacyAuthorizationDocument = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(legacy.schema_version, AUTHORIZATION_SCHEMA_VERSION);
    assert_eq!(legacy.server_id, state.server_id);
    assert!(legacy.invitations.is_empty());
    assert!(legacy.enrollment_receipts.is_empty());
    assert_eq!(state.key_rotations.len(), 1);
    let alice = legacy
        .members
        .iter()
        .find(|member| member.id == member_id)
        .unwrap();
    assert_eq!(alice.name, "Alice");
    assert_eq!(alice.role, ServerRole::Member);
    assert_eq!(
        legacy
            .devices
            .iter()
            .filter(|device| device.member_id == member_id)
            .count(),
        2
    );
}
