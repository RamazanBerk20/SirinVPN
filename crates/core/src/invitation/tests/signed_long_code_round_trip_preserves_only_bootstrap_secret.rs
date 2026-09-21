use super::*;

#[test]
fn signed_long_code_round_trip_preserves_only_bootstrap_secret() {
    let (mut profile, server_key) = owner_profile();
    profile.tcp_fallback = Some(TcpFallbackEndpoint {
        port: 443,
        server_public_key: STANDARD.encode([12_u8; 32]),
    });
    profile.tls_like = Some(TlsLikeEndpoint {
        port: 443,
        server_public_key: STANDARD.encode([12_u8; 32]),
        certificate_sha256: STANDARD.encode([13_u8; 32]),
        https: None,
    });
    let draft = InvitationDraft::new(&profile, "Alice", "Laptop", 600).unwrap();
    let response = signed_response(&profile, draft.request(), &server_key);
    let legacy_claims_shape = serde_json::to_value(&response.claims).unwrap();
    assert!(legacy_claims_shape.get("target_member_id").is_none());
    assert!(legacy_claims_shape.get("target_role").is_none());
    assert!(legacy_claims_shape.get("administrator").is_none());
    let code = draft.finish(response).unwrap();
    assert!(code.expose().starts_with(CODE_PREFIX));
    assert!(code.expose().len() < MAX_CODE_LENGTH);
    let decoded = DecodedInvitation::decode(code.expose()).unwrap();
    assert_eq!(decoded.member_name(), "Alice");
    assert_eq!(decoded.device_name(), "Laptop");
    let binding = decoded.enrollment_binding();
    assert_eq!(binding.server_id, profile.id);
    assert_eq!(binding.endpoint, profile.endpoint);
    assert_eq!(binding.role, ServerRole::Member);
    assert_eq!(binding.device_id, decoded.device_id());
    assert_eq!(
        decoded.bootstrap_profile().tcp_fallback,
        profile.tcp_fallback
    );
    assert_eq!(binding.tls_like, profile.tls_like);
    assert_eq!(decoded.bootstrap_profile().tls_like, profile.tls_like);
    assert!(!format!("{decoded:?}").contains("PRIVATE KEY"));
    assert!(code.qr_payload().len() < code.expose().len());
    assert!(QrCode::with_error_correction_level(code.qr_payload(), EcLevel::L).is_ok());
    let decoded_qr = DecodedInvitation::decode(code.qr_payload()).unwrap();
    assert_eq!(decoded_qr.invitation_id(), decoded.invitation_id());
}

#[test]
fn existing_member_invitation_binds_member_access_and_permanent_profile() {
    let (profile, server_key) = owner_profile();
    let target_member_id = MemberId::new();
    let draft = InvitationDraft::new_for_target(
        &profile,
        "Alice",
        "Tablet",
        600,
        InvitationTarget {
            member_id: Some(target_member_id),
            role: Some(ServerRole::Member),
            administrator: true,
        },
    )
    .unwrap();
    let response = signed_response(&profile, draft.request(), &server_key);
    let code = draft.finish(response).unwrap();
    let decoded = DecodedInvitation::decode(code.qr_payload()).unwrap();
    let permanent = LocalIdentity::generate("Alice tablet").unwrap();
    let claims = &decoded.response.claims;
    let result = EnrollmentResult {
        names: None,
        alternate_endpoint_hosts: Vec::new(),
        endpoint_discovery_port: None,
        server_id: claims.server_id,
        member_id: target_member_id,
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
    let permanent_profile = decoded
        .permanent_profile(&result, &permanent.public, "alice-tablet".to_owned())
        .unwrap();
    assert_eq!(permanent_profile.member_id, Some(target_member_id));
    assert!(permanent_profile.administrator);

    let mut wrong_access = result;
    wrong_access.administrator = false;
    assert!(matches!(
        decoded.permanent_profile(&wrong_access, &permanent.public, "alice-tablet".to_owned()),
        Err(InvitationError::EnrollmentMismatch)
    ));
}

#[test]
fn additional_owner_device_keeps_owner_role_without_admin_flag() {
    let (profile, server_key) = owner_profile();
    let owner_member_id = MemberId::new();
    let draft = InvitationDraft::new_for_target(
        &profile,
        "Owner",
        "Second laptop",
        600,
        InvitationTarget {
            member_id: Some(owner_member_id),
            role: Some(ServerRole::Owner),
            administrator: false,
        },
    )
    .unwrap();
    let mut response = signed_response(&profile, draft.request(), &server_key);
    response.claims.target_role = Some(ServerRole::Owner);
    let key = SigningKey::from_pkcs8_pem(&server_key).unwrap();
    response.signature = STANDARD.encode(
        key.sign(&serde_json::to_vec(&response.claims).unwrap())
            .to_bytes(),
    );
    let code = draft.finish(response).unwrap();
    let decoded = DecodedInvitation::decode(code.expose()).unwrap();
    let permanent = LocalIdentity::generate("Second owner laptop").unwrap();
    let claims = &decoded.response.claims;
    let profile = decoded
        .permanent_profile(
            &EnrollmentResult {
                names: None,
                alternate_endpoint_hosts: Vec::new(),
                endpoint_discovery_port: None,
                server_id: claims.server_id,
                member_id: owner_member_id,
                device_id: claims.device_id,
                role: ServerRole::Owner,
                administrator: false,
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
            },
            &permanent.public,
            "second-owner".to_owned(),
        )
        .unwrap();
    assert_eq!(profile.role, ServerRole::Owner);
    assert!(!profile.administrator);
    assert_eq!(profile.member_id, Some(owner_member_id));
}

#[test]
fn oversized_compressed_invitation_is_rejected_before_json_parsing() {
    let oversized = vec![b'x'; MAX_PAYLOAD_LENGTH + 1];
    let encoded = encode_qr_payload(&oversized).unwrap();
    assert!(matches!(
        DecodedInvitation::decode(&encoded),
        Err(InvitationError::InvalidCode)
    ));
}

#[test]
fn tampered_code_is_rejected() {
    let (profile, server_key) = owner_profile();
    let draft = InvitationDraft::new(&profile, "Alice", "Laptop", 600).unwrap();
    let response = signed_response(&profile, draft.request(), &server_key);
    let code = draft.finish(response).unwrap();
    let mut tampered = code.expose().as_bytes().to_vec();
    let last = tampered.last_mut().unwrap();
    *last = if *last == b'A' { b'B' } else { b'A' };
    assert!(DecodedInvitation::decode(std::str::from_utf8(&tampered).unwrap()).is_err());
}

#[test]
fn response_with_a_modified_signature_is_rejected_before_encoding() {
    let (profile, server_key) = owner_profile();
    let draft = InvitationDraft::new(&profile, "Alice", "Laptop", 600).unwrap();
    let mut response = signed_response(&profile, draft.request(), &server_key);
    let replacement = if response.signature.starts_with('A') {
        "B"
    } else {
        "A"
    };
    response.signature.replace_range(..1, replacement);
    assert!(matches!(
        draft.finish(response),
        Err(InvitationError::InvalidSignature)
    ));
}

#[test]
fn permanent_profile_is_bound_to_the_enrollment_result() {
    let (profile, server_key) = owner_profile();
    let draft = InvitationDraft::new(&profile, "Alice", "Laptop", 600).unwrap();
    let response = signed_response(&profile, draft.request(), &server_key);
    let code = draft.finish(response).unwrap();
    let decoded = DecodedInvitation::decode(code.expose()).unwrap();
    let permanent = LocalIdentity::generate("Alice laptop").unwrap();
    let claims = &decoded.response.claims;
    let result = EnrollmentResult {
        names: None,
        alternate_endpoint_hosts: Vec::new(),
        endpoint_discovery_port: None,
        server_id: claims.server_id,
        member_id: claims.member_id,
        device_id: claims.device_id,
        role: claims.role,
        administrator: claims.administrator,
        server_name: claims.server_name.clone(),
        endpoint: claims.endpoint.clone(),
        endpoint_generation: claims.endpoint_generation,
        client_tunnel_address: claims.client_tunnel_address,
        server_tunnel_address: claims.server_tunnel_address,
        ipv6_tunnel_enabled: true,
        server_wireguard_public_key: claims.server_wireguard_public_key.clone(),
        pinned_server_certificate_pem: claims.pinned_server_certificate_pem.clone(),
        obfuscated_udp: claims.obfuscated_udp.clone(),
        tcp_fallback: claims.tcp_fallback.clone(),
        tls_like: claims.tls_like.clone(),
    };
    let permanent_profile = decoded
        .permanent_profile(&result, &permanent.public, "new-device".to_owned())
        .unwrap();
    assert_eq!(permanent_profile.device_id, Some(claims.device_id));
    assert!(permanent_profile.ipv6_tunnel_enabled);
    assert_eq!(
        permanent_profile.client_management_certificate_pem,
        permanent.public.management_certificate_pem
    );
}
