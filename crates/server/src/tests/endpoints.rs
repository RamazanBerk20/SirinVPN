use super::*;
mod kernel;

fn initial() -> (
    tempfile::TempDir,
    ServerPaths,
    LocalIdentity,
    ServerId,
    BootstrapResult,
) {
    let directory = tempfile::tempdir().unwrap();
    let paths = ServerPaths::under(directory.path().join("state"));
    let owner = LocalIdentity::generate("Endpoint owner").unwrap();
    let id = ServerId::new();
    let result = initialize_with_transport_capabilities(
        &paths,
        "Endpoint VPS",
        &owner.public.management_certificate_pem,
        id,
        &owner.public.wireguard_public_key,
        51820,
        ServerCapabilities {
            obfuscated_udp_port: Some(4443),
            tcp_fallback_port: Some(443),
            tls_like_port: Some(443),
            public_host: Some("8.8.8.8".into()),
            alternate_endpoint_hosts: Some(vec!["2001:db8::8".into()]),
            ..Default::default()
        },
    )
    .unwrap();
    (directory, paths, owner, id, result)
}

#[test]
fn root_port_changes_publish_an_idempotent_checkpoint_and_keep_the_original_discovery_port() {
    let (_directory, paths, owner, id, first) = initial();
    let head = first.endpoint_transition.unwrap();
    assert_eq!(head.claims.generation, 1);
    assert_eq!(head.claims.previous_endpoint, head.claims.endpoint);
    assert_eq!(head.claims.endpoint_discovery_port, Some(443));
    let key = fs::read(&paths.wireguard_private_key).unwrap();
    let capabilities = ServerCapabilities {
        obfuscated_udp_port: Some(7443),
        tcp_fallback_port: Some(7444),
        tls_like_port: Some(7444),
        public_host: Some("8.8.8.8".into()),
        alternate_endpoint_hosts: Some(vec!["2001:db8::8".into()]),
        update_transport_ports: true,
        ..Default::default()
    };
    let next = initialize_with_transport_capabilities(
        &paths,
        "Endpoint VPS",
        &owner.public.management_certificate_pem,
        id,
        &owner.public.wireguard_public_key,
        51821,
        capabilities.clone(),
    )
    .unwrap();
    let updated = next.endpoint_transition.unwrap();
    assert_eq!(updated.claims.generation, 2);
    assert_eq!(updated.claims.endpoint_discovery_port, Some(443));
    assert_eq!(
        updated.claims.previous_transports,
        Some(head.claims.endpoint_descriptor())
    );
    assert_eq!(updated.claims.tls_like.as_ref().unwrap().port, 7444);
    assert_eq!(
        updated.claims.authorization_fingerprint,
        head.claims.authorization_fingerprint
    );
    assert_eq!(fs::read(&paths.wireguard_private_key).unwrap(), key);
    let retry = initialize_with_transport_capabilities(
        &paths,
        "Endpoint VPS",
        &owner.public.management_certificate_pem,
        id,
        &owner.public.wireguard_public_key,
        51821,
        capabilities,
    )
    .unwrap();
    assert_eq!(retry.endpoint_transition, Some(updated.clone()));
    assert_eq!(load_configuration(&paths).unwrap().schema_version, 8);
    assert_eq!(
        load_authorization(&paths.authorization)
            .unwrap()
            .schema_version,
        5
    );
    sirinvpn_core::DecodedEndpointTransition::from_response(updated).unwrap();
}

#[test]
fn a_read_only_handoff_backup_binds_old_ports_to_the_signed_predecessor() {
    let (directory, paths, owner, id, first) = initial();
    let backup = export_backup_state(&paths, id, &owner.public.management_certificate_pem).unwrap();
    let destination = ServerPaths::under(directory.path().join("restored"));
    fs::create_dir_all(&destination.state_directory).unwrap();
    restore_backup_state(
        &destination,
        id,
        &owner.public.management_certificate_pem,
        &backup,
    )
    .unwrap();
    let updated = initialize_with_transport_capabilities(
        &destination,
        "Endpoint VPS",
        &owner.public.management_certificate_pem,
        id,
        &owner.public.wireguard_public_key,
        51821,
        ServerCapabilities {
            obfuscated_udp_port: Some(7443),
            tcp_fallback_port: Some(7444),
            tls_like_port: Some(7444),
            public_host: Some("9.9.9.9".into()),
            update_transport_ports: true,
            ..Default::default()
        },
    )
    .unwrap()
    .endpoint_transition
    .unwrap();
    assert_eq!(
        updated.claims.previous_transports,
        Some(
            first
                .endpoint_transition
                .unwrap()
                .claims
                .endpoint_descriptor()
        )
    );
    let mut source = load_authorization(&paths.authorization).unwrap();
    source.accept_endpoint_transition(updated).unwrap();
    source.endpoint_transition_source = true;
    write_authorization(&paths.authorization, &source).unwrap();
    let backup = export_backup_state(&paths, id, &owner.public.management_certificate_pem).unwrap();
    let archive = directory.path().join("old-source.sirinvpn");
    write_encrypted_server_backup(&archive, &backup, "Endpoint test password").unwrap();
    let decoded = read_encrypted_server_backup(&archive, "Endpoint test password").unwrap();
    assert_eq!(decoded.metadata().endpoint_generation, 2);
    assert_eq!(decoded.metadata().wireguard_port, 51820);
    assert_eq!(decoded.metadata().endpoint_discovery_port, Some(443));
}

#[tokio::test]
async fn publishing_the_active_targets_own_checkpoint_never_freezes_its_authority() {
    let (_directory, paths, owner, id, bootstrap) = initial();
    let state = AppState {
        measurement_ready: false,
        configuration: load_configuration(&paths).unwrap(),
        operational_configuration: None,
        authorization: Some(Arc::new(RwLock::new(
            load_authorization(&paths.authorization).unwrap(),
        ))),
        paths,
        redemption_failures: Arc::new(Mutex::new(HashMap::new())),
        live_metrics: Arc::new(Mutex::new(LiveMetricSampler::default())),
        transport_peers: AuthorizedPeers::default(),
        transport_activity: ActiveTransportRegistry::default(),
    };
    let (result, received) = tokio::sync::oneshot::channel();
    endpoint_transition::publish_from_transport(
        &state,
        sirinvpn_transport::EndpointPublicationRequest {
            device_public_key: decode_key(&owner.public.wireguard_public_key).unwrap(),
            checkpoint: serde_json::to_vec(&bootstrap.endpoint_transition.unwrap()).unwrap(),
            result,
        },
    )
    .await;
    assert!(received.await.unwrap());
    let current = state.authorization.as_ref().unwrap().read().await;
    assert_eq!(current.server_id, id);
    assert!(!current.endpoint_transition_source);
}
