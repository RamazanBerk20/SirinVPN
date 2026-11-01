use super::*;

#[test]
fn quic_marks_schema_11_in_the_signed_endpoint_and_needs_its_own_udp_port() {
    let directory = tempfile::tempdir().unwrap();
    let paths = ServerPaths::under(directory.path().join("state"));
    let owner = LocalIdentity::generate("Owner").unwrap();
    let server_id = ServerId::new();
    let mut capabilities = ServerCapabilities {
        obfuscated_udp_port: Some(443),
        tcp_fallback_port: Some(443),
        tls_like_port: Some(443),
        public_host: Some("8.8.8.8".into()),
        update_transport_ports: true,
        quic: Some(true),
        ..Default::default()
    };
    let initialize = |capabilities: &ServerCapabilities| {
        initialize_with_transport_capabilities(
            &paths,
            "QUIC VPS",
            &owner.public.management_certificate_pem,
            server_id,
            &owner.public.wireguard_public_key,
            51_820,
            capabilities.clone(),
        )
    };
    // Two listeners cannot share UDP 443.
    assert!(initialize(&capabilities).is_err());
    assert!(!paths.configuration.exists());

    capabilities.obfuscated_udp_port = Some(51_821);
    let result = initialize(&capabilities).unwrap();
    let configuration = load_configuration(&paths).unwrap();
    assert_eq!(configuration.schema_version, 11);
    assert!(configuration.tls_like.as_ref().unwrap().quic);
    assert!(configuration.https_certificate_pem.is_some());
    assert!(result.tls_like.as_ref().unwrap().quic);
    let claims = result.endpoint_transition.unwrap().claims;
    assert!(claims.tls_like.as_ref().unwrap().quic);
    assert!(
        serde_json::to_string(&claims)
            .unwrap()
            .contains(r#""quic":true"#)
    );
    validate_state(&paths).unwrap();

    // Keeping the current setting, then turning QUIC off, publishes a new checkpoint.
    capabilities.quic = None;
    let kept = initialize(&capabilities).unwrap();
    assert_eq!(
        kept.endpoint_transition.unwrap().claims.generation,
        claims.generation
    );
    capabilities.quic = Some(false);
    let off = initialize(&capabilities).unwrap();
    let configuration = load_configuration(&paths).unwrap();
    assert_eq!(configuration.schema_version, 9);
    let off_claims = off.endpoint_transition.unwrap().claims;
    assert!(off_claims.generation > claims.generation);
    // The checkpoint still names the previous transports, which had QUIC.
    assert!(
        !serde_json::to_string(&off_claims.endpoint_descriptor())
            .unwrap()
            .contains("quic")
    );
    assert!(
        off_claims
            .previous_transports
            .unwrap()
            .tls_like
            .unwrap()
            .quic
    );

    // A hand-edited configuration cannot claim QUIC on Obfuscated UDP's port.
    let mut shared = configuration.clone();
    shared.schema_version = 11;
    shared.tls_like.as_mut().unwrap().quic = true;
    shared.obfuscated_udp.as_mut().unwrap().port = 443;
    assert!(configuration::validate_configuration(&shared).is_err());
    shared.obfuscated_udp.as_mut().unwrap().port = 51_821;
    configuration::validate_configuration(&shared).unwrap();
    shared.schema_version = 9;
    assert!(configuration::validate_configuration(&shared).is_err());
}
