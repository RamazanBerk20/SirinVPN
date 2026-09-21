use super::*;

#[test]
fn tcp_transport_uses_a_tagged_runtime_config_that_legacy_helpers_reject() {
    let directory = tempfile::tempdir().unwrap();
    let runner = RecordingRunner::default();
    let helper = LinuxNetworkHelper::new(runner.clone(), directory.path().to_path_buf());
    let mut request = request();
    request.schema_version = 4;
    request.endpoint_port = 443;
    request.transport = TransportKind::TcpFallback;
    request.server_transport_public_key = Some(STANDARD.encode([9_u8; 32]));
    request.mtu = 1_280;

    let status = helper.connect(&request).unwrap();
    assert_eq!(status.transport, Some(TransportKind::TcpFallback));
    let transport_path = helper.carrier_config_path(TransportKind::TcpFallback);
    let bytes = fs::read(&transport_path).unwrap();
    assert!(serde_json::from_slice::<ClientRelayConfig>(&bytes).is_err());
    let config: ClientTransportConfig = serde_json::from_slice(&bytes).unwrap();
    let ClientTransportConfig::Current(CurrentClientTransportConfig::TcpFallback(config)) = config
    else {
        panic!("TCP must use the tagged current runtime shape");
    };
    assert_eq!(config.server_address, "203.0.113.8:443".parse().unwrap());
    assert_eq!(config.local_listen.port(), TCP_CLIENT_RELAY_PORT);
    assert!(
        runner
            .commands
            .lock()
            .unwrap()
            .iter()
            .any(|(program, arguments, _)| {
                program == "wg"
                    && arguments.windows(2).any(|pair| {
                        pair[0] == "endpoint"
                            && pair[1] == format!("127.0.0.1:{TCP_CLIENT_RELAY_PORT}")
                    })
            })
    );
}

#[test]
fn legacy_runtime_and_status_shapes_default_transport_safely() {
    let server_id = ServerId(Uuid::new_v4());
    let runtime: RuntimeState = serde_json::from_value(serde_json::json!({
        "schema_version": 1,
        "server_id": server_id
    }))
    .unwrap();
    assert_eq!(runtime.transport, TransportKind::DirectUdp);
    assert_eq!(runtime.routing, TunnelRoutingPolicy::default());
    assert_eq!(runtime.dns_address, None);
    let serialized_runtime = serde_json::to_value(runtime).unwrap();
    assert!(serialized_runtime.get("transport").is_none());
    assert!(serialized_runtime.get("routing").is_none());
    assert!(serialized_runtime.get("dns_address").is_none());

    let status: LocalTunnelStatus = serde_json::from_value(serde_json::json!({
        "state": "connected",
        "interface_name": INTERFACE_NAME,
        "server_id": server_id,
        "rx_bytes": 1,
        "tx_bytes": 2,
        "ipv6_blocked": true
    }))
    .unwrap();
    assert_eq!(status.transport, None);
    assert_eq!(status.routing_mode, TunnelRoutingMode::FullTunnel);
    assert!(!status.allow_lan);
}

#[test]
fn dual_stack_apply_and_cleanup_own_both_routing_families() {
    let directory = tempfile::tempdir().unwrap();
    let runner = RecordingRunner::default();
    let helper = LinuxNetworkHelper::new(runner.clone(), directory.path().to_path_buf());
    let mut request = request();
    request.schema_version = 2;
    let client_ipv6 = ipv6_tunnel_address(request.server_id, request.client_address).unwrap();
    request.client_ipv6_address = Some(client_ipv6);

    helper.connect(&request).unwrap();
    {
        let commands = runner.commands.lock().unwrap();
        assert!(commands.iter().any(|(program, arguments, _)| {
            program == "wg"
                && arguments
                    .windows(2)
                    .any(|pair| pair == ["allowed-ips", "0.0.0.0/0,::/0"])
        }));
        assert!(commands.iter().any(|(program, arguments, _)| {
            program == "ip"
                && arguments
                    == &[
                        "-6",
                        "address",
                        "replace",
                        &format!("{client_ipv6}/128"),
                        "dev",
                        INTERFACE_NAME,
                        "nodad",
                    ]
        }));
        assert!(commands.iter().any(|(program, arguments, _)| {
            program == "ip"
                && arguments
                    == &[
                        "-6",
                        "route",
                        "add",
                        "default",
                        "dev",
                        INTERFACE_NAME,
                        "table",
                        ROUTING_TABLE,
                    ]
        }));
        assert!(commands.iter().any(|(program, arguments, _)| {
            program == "ip"
                && arguments
                    .iter()
                    .take(3)
                    .map(String::as_str)
                    .eq(["-6", "rule", "add"])
                && arguments.contains(&RULE_TUNNEL_PRIORITY.to_owned())
        }));
        assert!(!commands.iter().any(|(program, arguments, stdin)| {
            program == "nft"
                && arguments == &["-f", "-"]
                && String::from_utf8_lossy(stdin).contains("sirinvpn_client6")
        }));
    }

    helper.disconnect().unwrap();
    let commands = runner.commands.lock().unwrap();
    assert!(commands.iter().any(|(program, arguments, _)| {
        program == "ip"
            && arguments
                .iter()
                .take(3)
                .map(String::as_str)
                .eq(["-6", "rule", "delete"])
    }));
    assert!(commands.iter().any(|(program, arguments, _)| {
        program == "ip"
            && arguments
                == &[
                    "-6",
                    "route",
                    "delete",
                    "default",
                    "dev",
                    INTERFACE_NAME,
                    "table",
                    ROUTING_TABLE,
                ]
    }));
}

#[test]
fn ipv4_only_transient_sessions_keep_the_ipv6_leak_block() {
    let directory = tempfile::tempdir().unwrap();
    let runner = RecordingRunner::default();
    let helper = LinuxNetworkHelper::new(runner.clone(), directory.path().to_path_buf());

    let status = helper.connect(&request()).unwrap();

    assert!(status.ipv6_blocked);
    assert_eq!(status.transport, Some(TransportKind::DirectUdp));
    assert!(
        runner
            .commands
            .lock()
            .unwrap()
            .iter()
            .any(|(program, arguments, stdin)| {
                program == "nft"
                    && arguments == &["-f", "-"]
                    && String::from_utf8_lossy(stdin).contains("sirinvpn_client6")
            })
    );
}

#[test]
fn refuses_to_take_over_an_existing_policy_route_table() {
    let directory = tempfile::tempdir().unwrap();
    let runner = RecordingRunner {
        route_conflict: true,
        ..RecordingRunner::default()
    };
    let helper = LinuxNetworkHelper::new(runner.clone(), directory.path().to_path_buf());
    assert!(matches!(
        helper.connect(&request()),
        Err(HelperError::OwnershipConflict)
    ));
    assert!(
        !runner
            .commands
            .lock()
            .unwrap()
            .iter()
            .any(|(program, arguments, _)| program == "ip"
                && arguments.contains(&"add".to_owned()))
    );
}

#[test]
fn accepts_an_absent_policy_route_table() {
    let directory = tempfile::tempdir().unwrap();
    let runner = RecordingRunner::default();
    let helper = LinuxNetworkHelper::new(runner.clone(), directory.path().to_path_buf());

    helper.connect(&request()).unwrap();

    let commands = runner.commands.lock().unwrap();
    assert!(commands.iter().any(|(program, arguments, _)| {
        program == "ip" && arguments == &["-details", "-4", "route", "show", "table", "all"]
    }));
}

#[test]
fn retains_ownership_state_when_cleanup_leaves_kernel_residue() {
    let directory = tempfile::tempdir().unwrap();
    let runner = RecordingRunner {
        fail_apply: true,
        cleanup_residue: true,
        ..RecordingRunner::default()
    };
    let helper = LinuxNetworkHelper::new(runner, directory.path().to_path_buf());

    assert!(matches!(
        helper.connect(&request()),
        Err(HelperError::NetworkOperationFailed)
    ));
    assert!(directory.path().join("client-state.json").exists());
}

#[test]
fn persistent_protection_is_persisted_root_only_and_started_before_network_changes() {
    let directory = tempfile::tempdir().unwrap();
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let runner = RecordingRunner::default();
    let helper = LinuxNetworkHelper::new(runner.clone(), directory.path().to_path_buf());
    let mut request = request();
    request.persistent_protection = true;

    let status = helper.connect(&request).unwrap();

    assert!(status.kill_switch_enabled);
    assert!(status.auto_reconnect_enabled);
    assert_eq!(
        fs::metadata(directory.path()).unwrap().permissions().mode() & 0o777,
        0o755
    );
    assert_eq!(
        fs::metadata(directory.path().join("persistent"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    let desired = directory.path().join("persistent/desired-connection.json");
    assert_eq!(
        fs::metadata(&desired).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(
        fs::metadata(directory.path().join("client-state.json"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o644
    );
    assert!(String::from_utf8_lossy(&fs::read(&desired).unwrap()).contains(&request.private_key));
    let persisted: serde_json::Value = serde_json::from_slice(&fs::read(desired).unwrap()).unwrap();
    assert!(persisted["request"].get("transport").is_none());
    assert!(persisted.get("obfuscated_udp").is_none());

    let commands = runner.commands.lock().unwrap();
    let service_start = commands
        .iter()
        .position(|(program, arguments, _)| {
            program == "systemctl" && arguments == &["restart", RECONNECT_UNIT]
        })
        .unwrap();
    let guard_apply = commands
        .iter()
        .position(|(program, arguments, stdin)| {
            program == "nft"
                && arguments == &["-f", "-"]
                && String::from_utf8_lossy(stdin).contains("sirinvpn_guard")
        })
        .unwrap();
    assert!(service_start < guard_apply);
    assert!(
        commands
            .iter()
            .all(|(_, arguments, _)| { !arguments.contains(&request.private_key) })
    );
}

#[test]
fn automatic_persistent_state_remains_readable_by_protocol_six_helpers() {
    let directory = tempfile::tempdir().unwrap();
    let runner = RecordingRunner::default();
    let helper = LinuxNetworkHelper::new(runner, directory.path().to_path_buf());
    let request = persistent_automatic_request();

    let status = helper.connect(&request).unwrap();

    assert!(status.transport_fallback_enabled);
    let desired = directory.path().join("persistent/desired-connection.json");
    let bytes = fs::read(&desired).unwrap();
    let persisted: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        persisted["request"]["reconnect_candidates"]
            .as_array()
            .unwrap()
            .len(),
        3
    );
    for forbidden in [
        "management_private_key",
        "network_identity",
        "failure_history",
        "success_history",
    ] {
        assert!(!String::from_utf8_lossy(&bytes).contains(forbidden));
    }

    let legacy: LegacyPersistentConnectionV6 = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(legacy.schema_version, 1);
    assert_eq!(legacy.endpoint, Ipv4Addr::new(203, 0, 113, 8));
    assert_eq!(legacy.request.schema_version, 2);
    assert_eq!(legacy.request.transport, TransportKind::DirectUdp);
    assert_eq!(legacy.request.endpoint_port, 51_820);
    assert!(legacy.request.persistent_protection);
    assert!(legacy.obfuscated_udp.is_none());
    assert!(legacy.tcp_fallback.is_none());

    let current = helper.read_persistent().unwrap();
    assert_eq!(current.request.reconnect_candidates.len(), 3);
    assert_eq!(current.request.transport, TransportKind::DirectUdp);
}

#[test]
fn selected_persistent_state_reconnects_exactly_and_retains_legacy_full_fallback() {
    let directory = tempfile::tempdir().unwrap();
    let runner = RecordingRunner::default();
    let helper = LinuxNetworkHelper::new(runner.clone(), directory.path().to_path_buf());
    let mut selected = persistent_automatic_request();
    selected.schema_version = 6;
    selected.routing = TunnelRoutingPolicy::selected_routes(
        [
            "198.51.100.0/24".to_owned(),
            "2001:db8:1234::/48".to_owned(),
        ],
        true,
    )
    .unwrap();
    selected.client_ipv6_address = ipv6_tunnel_address(selected.server_id, selected.client_address);

    helper.connect(&selected).unwrap();

    let desired = directory.path().join("persistent/desired-connection.json");
    let bytes = fs::read(&desired).unwrap();
    let persisted: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(persisted["request"]["schema_version"], 2);
    assert!(persisted["request"].get("routing").is_none());
    assert_eq!(persisted["extended_routing"]["mode"], "selected_routes");
    let legacy: LegacyPersistentConnectionV6 = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(legacy.request.schema_version, 2);
    assert!(legacy.request.persistent_protection);

    let restored = helper.read_persistent().unwrap();
    assert_eq!(restored.request.schema_version, 6);
    assert_eq!(restored.request.routing, selected.routing);
    let next = next_persistent_request(&restored, TransportKind::DirectUdp);
    assert_eq!(next.schema_version, 6);
    assert_eq!(next.routing, selected.routing);

    let guard = runner
        .commands
        .lock()
        .unwrap()
        .iter()
        .rev()
        .find(|(program, arguments, input)| {
            program == "nft"
                && arguments == &["-f", "-"]
                && String::from_utf8_lossy(input).contains("sirinvpn_guard")
        })
        .map(|(_, _, input)| String::from_utf8_lossy(input).into_owned())
        .unwrap();
    assert!(guard.contains("policy accept"));
    assert!(guard.contains("udp dport { 53, 853 } drop"));
    assert!(guard.contains("ip daddr 198.51.100.0/24 oifname != \"sirinvpn0\" drop"));
    assert!(guard.contains("ip6 daddr 2001:db8:1234::/48"));
    assert!(guard.contains("ip daddr 192.168.0.0/16 accept"));
    assert!(!guard.contains("policy drop"));
}

#[test]
fn owned_route_and_rule_matching_is_exact_and_accepts_host_route_display() {
    let routes = b"unicast 10.77.0.1 dev sirinvpn0 table 51820 proto static\n\
unicast 198.51.100.0/24 dev wlo1 table 51820 proto static\n\
unicast 203.0.113.8/32 dev sirinvpn0 table main proto static\n";
    assert!(route_output_contains_owned_destination(
        routes,
        "10.77.0.1/32",
        ROUTING_TABLE,
    ));
    assert!(!route_output_contains_owned_destination(
        routes,
        "198.51.100.0/24",
        ROUTING_TABLE,
    ));
    assert!(!route_output_contains_owned_destination(
        routes,
        "203.0.113.8/32",
        ROUTING_TABLE,
    ));

    let rules = b"9990: from all to 10.77.0.1 lookup 51820\n\
9990: from all to 198.51.100.0/24 lookup main\n";
    assert!(rule_output_contains_destination_table(
        rules,
        "10.77.0.1/32",
        ROUTING_TABLE,
    ));
    assert!(!rule_output_contains_destination_table(
        rules,
        "198.51.100.0/24",
        ROUTING_TABLE,
    ));
}
