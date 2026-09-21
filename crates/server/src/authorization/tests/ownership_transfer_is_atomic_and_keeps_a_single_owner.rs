use super::*;

#[test]
fn ownership_transfer_is_atomic_and_keeps_a_single_owner() {
    let mut state = state();
    let previous_owner_id = state
        .members
        .iter()
        .find(|member| member.role == ServerRole::Owner)
        .unwrap()
        .id;
    let previous_owner_device_id = state
        .devices
        .iter()
        .find(|device| device.member_id == previous_owner_id)
        .unwrap()
        .id;
    let (destination_member_id, _) = add_member(&mut state, "Alice", false);
    let destination_device_id = state
        .devices
        .iter()
        .find(|device| device.member_id == destination_member_id)
        .unwrap()
        .id;

    state.transfer_ownership(destination_device_id).unwrap();
    state.validate().unwrap();
    let previous_owner = state
        .members
        .iter()
        .find(|member| member.id == previous_owner_id)
        .unwrap();
    let destination = state
        .members
        .iter()
        .find(|member| member.id == destination_member_id)
        .unwrap();
    assert_eq!(previous_owner.role, ServerRole::Member);
    assert!(previous_owner.administrator);
    assert_eq!(destination.role, ServerRole::Owner);
    assert!(!destination.administrator);

    state.transfer_ownership(previous_owner_device_id).unwrap();
    state.validate().unwrap();
    assert_eq!(
        state
            .members
            .iter()
            .find(|member| member.id == previous_owner_id)
            .unwrap()
            .role,
        ServerRole::Owner
    );
    assert!(
        state
            .members
            .iter()
            .find(|member| member.id == destination_member_id)
            .unwrap()
            .administrator
    );
}

#[test]
fn targeted_device_enrollment_receipt_resolves_to_existing_member() {
    let mut state = state();
    let (member_id, _) = add_member(&mut state, "Alice", true);
    let bootstrap = LocalIdentity::generate("Invitation bootstrap").unwrap();
    let permanent = LocalIdentity::generate("Alice tablet").unwrap();
    let server = LocalIdentity::generate("Server").unwrap();
    let claims = InvitationClaims {
        recipient_names: false,
        alternate_endpoint_hosts: Vec::new(),
        endpoint_discovery_port: None,
        max_uses: 1,
        member_policy: Default::default(),
        schema_version: 1,
        invitation_id: InvitationId::new(),
        server_id: state.server_id,
        server_name: "Test server".to_owned(),
        endpoint: ServerEndpoint {
            host: "203.0.113.4".to_owned(),
            wireguard_port: 51_820,
        },
        endpoint_generation: 0,
        server_tunnel_address: "10.77.0.1".parse().unwrap(),
        management_port: DEFAULT_MANAGEMENT_PORT,
        server_wireguard_public_key: server.public.wireguard_public_key,
        pinned_server_certificate_pem: server.public.management_certificate_pem,
        obfuscated_udp: None,
        tcp_fallback: None,
        tls_like: None,
        member_id: MemberId::new(),
        target_member_id: Some(member_id),
        target_role: Some(ServerRole::Member),
        device_id: DeviceId::new(),
        member_name: "Alice".to_owned(),
        device_name: "Tablet".to_owned(),
        role: ServerRole::Member,
        administrator: true,
        client_tunnel_address: state.allocate_member_address().unwrap(),
        bootstrap_tunnel_address: state.allocate_bootstrap_address().unwrap(),
        expires_at_unix: 1_000,
        token_hash: "00".repeat(32),
        bootstrap_wireguard_public_key: bootstrap.public.wireguard_public_key.clone(),
        bootstrap_management_certificate_pem: bootstrap.public.management_certificate_pem.clone(),
    };
    state.invitations.push(InvitationRecord {
        issued_by: None,
        uses_consumed: 0,
        claims: claims.clone(),
        signature: "test signature".to_owned(),
    });
    state.validate().unwrap();

    let original_device_id = state
        .devices
        .iter()
        .find(|device| device.member_id == member_id)
        .unwrap()
        .id;
    assert!(
        state
            .clone()
            .transfer_ownership(original_device_id)
            .is_err()
    );
    let mut removed_member = state.clone();
    removed_member.remove_device_and_dependents(original_device_id, member_id);
    assert!(
        removed_member
            .members
            .iter()
            .all(|member| member.id != member_id)
    );
    assert!(removed_member.invitations.is_empty());
    removed_member.validate().unwrap();

    state.invitations.clear();
    let permanent_fingerprint =
        certificate_fingerprint(&permanent.public.management_certificate_pem).unwrap();
    state.devices.push(DeviceRecord {
        id: claims.device_id,
        member_id,
        name: claims.device_name.clone(),
        client_tunnel_address: claims.client_tunnel_address,
        wireguard_public_key: permanent.public.wireguard_public_key.clone(),
        management_certificate_pem: permanent.public.management_certificate_pem.clone(),
        certificate_fingerprint: permanent_fingerprint,
        peer_communication_enabled: false,
    });
    let result = EnrollmentResult {
        names: None,
        alternate_endpoint_hosts: Vec::new(),
        endpoint_discovery_port: None,
        server_id: claims.server_id,
        member_id,
        device_id: claims.device_id,
        role: ServerRole::Member,
        administrator: true,
        server_name: claims.server_name.clone(),
        endpoint: claims.endpoint.clone(),
        endpoint_generation: claims.endpoint_generation,
        client_tunnel_address: claims.client_tunnel_address,
        server_tunnel_address: claims.server_tunnel_address,
        ipv6_tunnel_enabled: false,
        server_wireguard_public_key: claims.server_wireguard_public_key.clone(),
        pinned_server_certificate_pem: claims.pinned_server_certificate_pem.clone(),
        obfuscated_udp: claims.obfuscated_udp.clone(),
        tcp_fallback: claims.tcp_fallback.clone(),
        tls_like: claims.tls_like.clone(),
    };
    state.enrollment_receipts.push(EnrollmentReceipt {
        invitation_id: claims.invitation_id,
        claims: claims.clone(),
        signature: "test signature".to_owned(),
        token_hash: claims.token_hash.clone(),
        bootstrap_tunnel_address: claims.bootstrap_tunnel_address,
        bootstrap_wireguard_public_key: claims.bootstrap_wireguard_public_key.clone(),
        bootstrap_management_certificate_pem: claims.bootstrap_management_certificate_pem.clone(),
        bootstrap_certificate_fingerprint: certificate_fingerprint(
            &claims.bootstrap_management_certificate_pem,
        )
        .unwrap(),
        device_wireguard_public_key: permanent.public.wireguard_public_key,
        device_management_certificate_pem: permanent.public.management_certificate_pem,
        result,
        expires_at_unix: 1_060,
    });
    state.validate().unwrap();
    assert!(
        state
            .clone()
            .transfer_ownership(original_device_id)
            .is_err()
    );
    assert_eq!(
        state
            .devices
            .iter()
            .filter(|device| device.member_id == member_id)
            .count(),
        2
    );

    let mut revoked = state.clone();
    revoked.remove_device_and_dependents(claims.device_id, member_id);
    assert!(revoked.enrollment_receipts.is_empty());
    assert_eq!(
        revoked
            .devices
            .iter()
            .filter(|device| device.member_id == member_id)
            .count(),
        1
    );
    revoked.validate().unwrap();

    assert!(state.prune_expired(1_061));
    assert!(state.enrollment_receipts.is_empty());
    state.validate().unwrap();
}
