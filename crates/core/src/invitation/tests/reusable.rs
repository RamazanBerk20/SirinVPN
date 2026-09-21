use super::*;

#[test]
fn reusable_signed_scope_accepts_unique_allocations_but_rejects_changed_authority() {
    let (profile, private_key) = owner_profile();
    let policy = sirinvpn_protocol::MemberPolicy {
        device_limit: Some(2),
        ..Default::default()
    };
    let draft = InvitationDraft::new(&profile, "Family", "Phone", 3600)
        .unwrap()
        .with_recipient_names(true)
        .with_policy(5, policy.clone())
        .unwrap();
    let response = signed_response(&profile, draft.request(), &private_key);
    assert_eq!(response.claims.schema_version, 2);
    let code = draft.finish(response.clone()).unwrap();
    let mut decoded = DecodedInvitation::decode(code.expose()).unwrap();
    decoded
        .set_recipient_names(Some("New member"), Some("Independent phone"))
        .unwrap();
    let permanent = LocalIdentity::generate("Phone").unwrap();
    let claims = &response.claims;
    let mut result = EnrollmentResult {
        names: decoded.enrollment_binding().names,
        alternate_endpoint_hosts: Vec::new(),
        endpoint_discovery_port: None,
        server_id: claims.server_id,
        member_id: MemberId::new(),
        device_id: DeviceId::new(),
        role: claims.role,
        administrator: false,
        server_name: claims.server_name.clone(),
        endpoint: claims.endpoint.clone(),
        endpoint_generation: claims.endpoint_generation,
        client_tunnel_address: "10.77.0.4".parse().unwrap(),
        server_tunnel_address: claims.server_tunnel_address,
        server_wireguard_public_key: claims.server_wireguard_public_key.clone(),
        pinned_server_certificate_pem: claims.pinned_server_certificate_pem.clone(),
        obfuscated_udp: claims.obfuscated_udp.clone(),
        tcp_fallback: claims.tcp_fallback.clone(),
        tls_like: claims.tls_like.clone(),
        ipv6_tunnel_enabled: false,
    };
    let enrolled = decoded
        .permanent_profile(&result, &permanent.public, "permanent".into())
        .unwrap();
    assert_eq!(enrolled.device_id, Some(result.device_id));
    assert!(decoded.enrollment_binding().reusable);
    result.names.as_mut().unwrap().device_name = "Different label".into();
    assert!(
        decoded
            .permanent_profile(&result, &permanent.public, "permanent".into())
            .is_err()
    );
    result.names = decoded.enrollment_binding().names;
    result.administrator = true;
    assert!(
        decoded
            .permanent_profile(&result, &permanent.public, "permanent".into())
            .is_err()
    );
    result.administrator = false;
    result.client_tunnel_address = "10.77.0.224".parse().unwrap();
    assert!(
        decoded
            .permanent_profile(&result, &permanent.public, "permanent".into())
            .is_err()
    );
    let mut tampered = response;
    tampered.claims.member_policy.invite_members = true;
    assert!(validate_invitation_response(&tampered).is_err());
}
