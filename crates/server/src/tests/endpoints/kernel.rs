use super::*;

async fn packets(mode: &str, data: serde_json::Value) {
    let mut child = Command::new("python3")
        .args(["tests/network/endpoint_handoff.py", mode])
        .stdin(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(&serde_json::to_vec(&data).unwrap())
        .await
        .unwrap();
    assert!(
        child.wait().await.unwrap().success(),
        "handoff packet checks: {mode}"
    );
}

#[tokio::test]
#[ignore = "requires disposable networking; use tests/network/run-endpoint-handoff.sh"]
async fn kernel_published_source_blocks_data_but_retains_control_across_restart() {
    assert_eq!(
        std::env::var("SIRINVPN_POLICY_ISOLATED").as_deref(),
        Ok("1")
    );
    assert!(Path::new("/.dockerenv").exists());
    let (directory, paths, owner, id, bootstrap) = initial();
    let mut configuration = load_configuration(&paths).unwrap();
    configuration.ipv6_tunnel_enabled = true;
    let before = load_authorization(&paths.authorization).unwrap();
    let owner_key = directory.path().join("owner.key");
    write_private(&owner_key, owner.secret.wireguard_private_key.as_bytes()).unwrap();
    let server_v6 = ipv6_tunnel_address(id, Ipv4Addr::new(10, 77, 0, 1)).unwrap();
    let owner_v6 = ipv6_tunnel_address(id, Ipv4Addr::new(10, 77, 0, 2)).unwrap();
    packets("prepare", serde_json::json!({
        "server_private_key_path": paths.wireguard_private_key,
        "server_ipv6": server_v6,
        "devices": [{"index": 0, "ipv4": "10.77.0.2", "ipv6": owner_v6, "private_key_path": owner_key}]
    })).await;
    let state = AppState {
        measurement_ready: false,
        configuration,
        operational_configuration: Some(OperationalConfiguration {
            schema_version: 1,
            external_interface: "eth-test".into(),
            ssh_port: 22,
        }),
        authorization: Some(Arc::new(RwLock::new(before.clone()))),
        paths,
        redemption_failures: Arc::new(Mutex::new(HashMap::new())),
        live_metrics: Arc::new(Mutex::new(LiveMetricSampler::default())),
        transport_peers: AuthorizedPeers::default(),
        transport_activity: ActiveTransportRegistry::default(),
    };
    sync_peer_isolation(&state.configuration, &before)
        .await
        .unwrap();
    sync_wireguard_peers(&state.configuration, &before)
        .await
        .unwrap();
    packets("open", serde_json::json!({"server_ipv6": server_v6})).await;

    let mut head = bootstrap.endpoint_transition.unwrap();
    head.claims.generation = 8;
    head.claims.endpoint.host = "9.9.9.9".into();
    head.signature = sign_endpoint_transition(&state.paths.tls_private_key, &head.claims).unwrap();
    let publish = || {
        publish_endpoint_transition_handler(
            State(state.clone()),
            Extension(CallerIdentity {
                certificate_fingerprint: before.devices[0].certificate_fingerprint.clone(),
            }),
            Json(head.clone()),
        )
    };
    fs::create_dir(state.paths.authorization.with_extension("new")).unwrap();
    assert!(publish().await.is_err());
    assert_eq!(*state.authorization.as_ref().unwrap().read().await, before);
    packets("open", serde_json::json!({"server_ipv6": server_v6})).await;
    fs::remove_dir(state.paths.authorization.with_extension("new")).unwrap();
    assert!(publish().await.is_ok());
    assert!(publish().await.is_ok());
    packets("source", serde_json::json!({"server_ipv6": server_v6})).await;
    let current = load_authorization(&state.paths.authorization).unwrap();
    assert!(current.endpoint_transition_source);
    assert_eq!(current.endpoint_generation(), 8);
    assert!(
        state
            .transport_peers
            .contains(&decode_key(&owner.public.wireguard_public_key).unwrap())
    );
    // Normal firewall replacement must not remove the source guard. The startup
    // command reconstructs it from persistent state before peers are restored.
    apply_nft_batch(
        "delete table inet sirinvpn_filter\n",
        "test firewall reload",
    )
    .await
    .unwrap();
    install_network_guard(&state.paths).await.unwrap();
    packets("source", serde_json::json!({"server_ipv6": server_v6})).await;
}
