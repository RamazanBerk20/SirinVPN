use super::*;

fn second_device(document: &mut AuthorizationDocument, member_id: MemberId) -> DeviceId {
    let identity = LocalIdentity::generate("Second device").unwrap();
    let device_id = DeviceId::new();
    document.devices.push(DeviceRecord {
        id: device_id,
        member_id,
        name: "Second device".into(),
        client_tunnel_address: document.allocate_member_address().unwrap(),
        wireguard_public_key: identity.public.wireguard_public_key.clone(),
        management_certificate_pem: identity.public.management_certificate_pem.clone(),
        certificate_fingerprint: certificate_fingerprint(
            &identity.public.management_certificate_pem,
        )
        .unwrap(),
        peer_communication_enabled: true,
    });
    device_id
}

#[test]
fn suspension_blocks_every_identity_and_retains_addresses_and_settings_for_reactivation() {
    let mut document = state();
    let (member_id, _) = add_member(&mut document, "Family", false);
    let second = second_device(&mut document, member_id);
    document
        .add_port_forward(PortForward {
            protocol: sirinvpn_protocol::PortForwardProtocol::Tcp,
            public_port: 9000,
            device_id: second,
            device_port: 8000,
        })
        .unwrap();
    let before = document.clone();
    let next_address = document.allocate_member_address().unwrap();
    document.set_member_suspended(member_id, true).unwrap();
    assert_eq!(document.devices, before.devices);
    assert_eq!(document.port_forwards, before.port_forwards);
    assert_eq!(document.allocate_member_address().unwrap(), next_address);
    assert_eq!(document.schema_version, 2);
    assert!(
        document
            .snapshot(1)
            .members
            .iter()
            .find(|member| member.id == member_id)
            .unwrap()
            .suspended
    );
    for device in document
        .devices
        .iter()
        .filter(|device| device.member_id == member_id)
    {
        assert!(document.access_for_device(device).is_none());
        assert!(
            document
                .device_for_fingerprint(&device.certificate_fingerprint)
                .is_none()
        );
        assert!(
            !document
                .desired_peers(1)
                .iter()
                .any(|peer| peer.public_key == device.wireguard_public_key)
        );
        assert!(
            !document
                .client_certificates(1)
                .contains(&device.management_certificate_pem)
        );
    }
    assert_eq!(document.desired_peers(1).len(), 1);
    let once = document.clone();
    document.set_member_suspended(member_id, true).unwrap();
    assert_eq!(document, once);
    document.set_member_suspended(member_id, false).unwrap();
    assert_eq!(document, before);
}

#[test]
fn bulk_revocation_removes_all_devices_and_forwards_without_touching_another_member() {
    let mut document = state();
    let (member_id, _) = add_member(&mut document, "Family", false);
    let second = second_device(&mut document, member_id);
    let (unrelated_id, _) = add_member(&mut document, "Other", false);
    document
        .add_port_forward(PortForward {
            protocol: sirinvpn_protocol::PortForwardProtocol::Udp,
            public_port: 9001,
            device_id: second,
            device_port: 8001,
        })
        .unwrap();
    let retained: Vec<_> = document
        .devices
        .iter()
        .filter(|device| device.member_id != member_id)
        .cloned()
        .collect();
    document.set_member_suspended(member_id, true).unwrap();
    document.revoke_member_devices(member_id).unwrap();
    assert_eq!(document.devices, retained);
    assert!(document.port_forwards.is_empty());
    assert!(!document.members.iter().any(|member| member.id == member_id));
    assert!(
        document
            .members
            .iter()
            .any(|member| member.id == unrelated_id)
    );
    assert_eq!(document.schema_version, 1);
    assert_eq!(
        document.allocate_member_address().unwrap().to_string(),
        "10.77.0.3"
    );
    document.validate().unwrap();
}

#[test]
fn owner_cannot_be_suspended_or_bulk_revoked_and_suspended_member_cannot_become_owner() {
    let mut document = state();
    let owner_id = document.members[0].id;
    let original = document.clone();
    assert!(document.set_member_suspended(owner_id, true).is_err());
    assert!(document.revoke_member_devices(owner_id).is_err());
    assert_eq!(document, original);
    let (member_id, _) = add_member(&mut document, "Admin", true);
    let device_id = document.devices.last().unwrap().id;
    document.set_member_suspended(member_id, true).unwrap();
    let suspended = document.clone();
    assert!(document.transfer_ownership(device_id).is_err());
    assert_eq!(document, suspended);
}

#[test]
fn suspension_requires_the_new_schema_and_survives_private_atomic_storage() {
    let mut document = state();
    let (member_id, _) = add_member(&mut document, "Family", false);
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("authorization.json");
    document.set_member_suspended(member_id, true).unwrap();
    write_authorization(&path, &document).unwrap();
    assert_eq!(load_authorization(&path).unwrap(), document);
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    #[derive(Deserialize)]
    struct LegacyHeader {
        schema_version: u16,
    }
    let header: LegacyHeader = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    assert_ne!(header.schema_version, AUTHORIZATION_SCHEMA_VERSION);
    document.schema_version = 1;
    assert!(document.validate().is_err());
    assert!(write_authorization(&path, &document).is_err());
    assert_eq!(load_authorization(&path).unwrap().schema_version, 2);
}

#[test]
fn member_lifecycle_cancels_pending_bootstrap_identities_and_rotations_permanently() {
    let mut document = state();
    let (member_id, _) = add_member(&mut document, "Family", false);
    let bootstrap = LocalIdentity::generate("Pending device").unwrap();
    let server = LocalIdentity::generate("Server").unwrap();
    let claims = InvitationClaims {
        recipient_names: false,
        alternate_endpoint_hosts: Vec::new(),
        endpoint_discovery_port: None,
        max_uses: 1,
        member_policy: Default::default(),
        schema_version: 1,
        invitation_id: InvitationId::new(),
        server_id: document.server_id,
        server_name: "Test server".into(),
        endpoint: ServerEndpoint {
            host: "203.0.113.4".into(),
            wireguard_port: 51820,
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
        member_name: "Family".into(),
        device_name: "Tablet".into(),
        role: ServerRole::Member,
        administrator: false,
        client_tunnel_address: document.allocate_member_address().unwrap(),
        bootstrap_tunnel_address: document.allocate_bootstrap_address().unwrap(),
        expires_at_unix: 2000,
        token_hash: "00".repeat(32),
        bootstrap_wireguard_public_key: bootstrap.public.wireguard_public_key.clone(),
        bootstrap_management_certificate_pem: bootstrap.public.management_certificate_pem.clone(),
    };
    document.invitations.push(InvitationRecord {
        issued_by: None,
        uses_consumed: 0,
        claims: claims.clone(),
        signature: "test signature".into(),
    });
    let new_identity = LocalIdentity::generate("Rotation").unwrap();
    let request = KeyRotationPrepareRequest {
        rotation_id: KeyRotationId::new(),
        server_id: document.server_id,
        new_wireguard_public_key: new_identity.public.wireguard_public_key,
        new_management_certificate_pem: new_identity.public.management_certificate_pem.clone(),
    };
    let fingerprint = document.devices[1].certificate_fingerprint.clone();
    document
        .prepare_key_rotation(&fingerprint, &request, 1000)
        .unwrap();
    let active = document.clone();
    document.set_member_suspended(member_id, true).unwrap();
    assert!(document.invitations.is_empty());
    assert!(document.key_rotations.is_empty());
    assert!(
        !document
            .client_certificates(1001)
            .contains(&bootstrap.public.management_certificate_pem)
    );
    assert!(
        !document
            .client_certificates(1001)
            .contains(&new_identity.public.management_certificate_pem)
    );
    document.set_member_suspended(member_id, false).unwrap();
    assert!(document.invitations.is_empty());
    assert!(
        document
            .commit_key_rotation(
                request.rotation_id,
                &certificate_fingerprint(&new_identity.public.management_certificate_pem).unwrap(),
                1002
            )
            .is_err()
    );

    // A redeemed invitation may retain a retry receipt and bootstrap peer briefly.
    let mut receipt_state = active;
    receipt_state.invitations.clear();
    receipt_state.key_rotations.clear();
    let device = receipt_state.devices[1].clone();
    let mut receipt_claims = claims;
    receipt_claims.device_id = device.id;
    receipt_claims.client_tunnel_address = device.client_tunnel_address;
    let mut result: EnrollmentResult =
        serde_json::from_value(serde_json::to_value(&receipt_claims).unwrap()).unwrap();
    result.member_id = member_id;
    receipt_state.enrollment_receipts.push(EnrollmentReceipt {
        invitation_id: receipt_claims.invitation_id,
        signature: "test signature".into(),
        token_hash: receipt_claims.token_hash.clone(),
        bootstrap_tunnel_address: receipt_claims.bootstrap_tunnel_address,
        bootstrap_wireguard_public_key: receipt_claims.bootstrap_wireguard_public_key.clone(),
        bootstrap_management_certificate_pem: receipt_claims
            .bootstrap_management_certificate_pem
            .clone(),
        bootstrap_certificate_fingerprint: certificate_fingerprint(
            &receipt_claims.bootstrap_management_certificate_pem,
        )
        .unwrap(),
        device_wireguard_public_key: device.wireguard_public_key,
        device_management_certificate_pem: device.management_certificate_pem,
        claims: receipt_claims,
        result,
        expires_at_unix: 2060,
    });
    receipt_state.validate().unwrap();
    let mut revoked = receipt_state.clone();
    revoked.revoke_member_devices(member_id).unwrap();
    assert!(revoked.enrollment_receipts.is_empty());
    receipt_state.set_member_suspended(member_id, true).unwrap();
    assert!(receipt_state.enrollment_receipts.is_empty());
    assert_eq!(receipt_state.desired_peers(1001).len(), 1);
    receipt_state
        .set_member_suspended(member_id, false)
        .unwrap();
    assert_eq!(receipt_state.desired_peers(1001).len(), 2);
    assert!(receipt_state.enrollment_receipts.is_empty());
}
