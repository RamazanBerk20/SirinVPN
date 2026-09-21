use super::*;

#[test]
fn private_key_is_only_sent_over_stdin() {
    let directory = tempfile::tempdir().unwrap();
    let runner = RecordingRunner::default();
    let helper = LinuxNetworkHelper::new(runner.clone(), directory.path().to_path_buf());
    helper.connect(&request()).unwrap();
    let commands = runner.commands.lock().unwrap();
    let key = STANDARD.encode([7_u8; 32]);
    assert!(
        commands
            .iter()
            .all(|(_, arguments, _)| !arguments.contains(&key))
    );
    assert!(commands.iter().any(|(program, _, stdin)| {
        program == "wg" && String::from_utf8_lossy(stdin).trim() == key
    }));
}

#[test]
fn rejects_invalid_keys_before_network_changes() {
    let directory = tempfile::tempdir().unwrap();
    let runner = RecordingRunner::default();
    let helper = LinuxNetworkHelper::new(runner.clone(), directory.path().to_path_buf());
    let mut request = request();
    request.private_key = "not-a-key".into();
    assert!(matches!(
        helper.connect(&request),
        Err(HelperError::InvalidConfiguration(_))
    ));
    assert!(runner.commands.lock().unwrap().is_empty());
}

#[test]
fn rejects_ipv6_addresses_not_derived_from_the_server_and_ipv4_host() {
    let directory = tempfile::tempdir().unwrap();
    let runner = RecordingRunner::default();
    let helper = LinuxNetworkHelper::new(runner.clone(), directory.path().to_path_buf());
    let mut request = request();
    request.schema_version = 2;
    request.client_ipv6_address = Some("fd00::99".parse().unwrap());

    assert!(matches!(
        helper.connect(&request),
        Err(HelperError::InvalidConfiguration(_))
    ));
    assert!(runner.commands.lock().unwrap().is_empty());

    request.schema_version = 1;
    request.client_ipv6_address = ipv6_tunnel_address(request.server_id, request.client_address);
    assert!(matches!(
        helper.connect(&request),
        Err(HelperError::InvalidConfiguration(_))
    ));
    assert!(runner.commands.lock().unwrap().is_empty());
}

#[test]
fn schema_one_requests_without_ipv6_remain_readable() {
    let request = request();
    let serialized = serde_json::to_value(&request).unwrap();
    assert!(serialized.get("client_ipv6_address").is_none());
    assert!(serialized.get("transport").is_none());
    assert!(serialized.get("server_transport_public_key").is_none());
    assert!(serialized.get("server_certificate_sha256").is_none());
    assert!(serialized.get("routing").is_none());

    let mut unsupported = serialized.clone();
    unsupported["transport"] = serde_json::json!("obfuscated_udp");
    let unsupported: TunnelConnectRequest = serde_json::from_value(unsupported).unwrap();
    assert!(validate_request(&unsupported).is_err());

    let decoded: TunnelConnectRequest = serde_json::from_value(serialized).unwrap();
    assert_eq!(decoded.schema_version, 1);
    assert_eq!(decoded.client_ipv6_address, None);
    assert_eq!(decoded.transport, TransportKind::DirectUdp);
    assert!(validate_request(&decoded).is_ok());
}

#[test]
fn selected_routes_are_canonical_bounded_and_versioned() {
    let routing = TunnelRoutingPolicy::selected_routes(
        [
            " 2001:db8:1234::7/48 ".to_owned(),
            "198.51.100.7/24".to_owned(),
            "198.51.100.0/24".to_owned(),
        ],
        true,
    )
    .unwrap();
    assert_eq!(
        routing.included_routes,
        ["198.51.100.0/24", "2001:db8:1234::/48"]
    );

    let mut selected = request();
    selected.schema_version = 6;
    selected.client_ipv6_address = ipv6_tunnel_address(selected.server_id, selected.client_address);
    selected.routing = routing;
    assert!(validate_request(&selected).is_ok());

    let mut legacy = selected.clone();
    legacy.schema_version = 2;
    assert!(validate_request(&legacy).is_err());

    let mut no_ipv6 = selected.clone();
    no_ipv6.client_ipv6_address = None;
    assert!(validate_request(&no_ipv6).is_err());

    assert!(TunnelRoutingPolicy::selected_routes(["0.0.0.0/0".to_owned()], false).is_err());
    assert!(
        TunnelRoutingPolicy::selected_routes(
            (0..=MAX_INCLUDED_ROUTES).map(|index| format!("198.51.100.{index}/32")),
            false,
        )
        .is_err()
    );
}

#[test]
fn selected_routes_apply_without_a_default_route_or_ipv6_leak_block() {
    let directory = tempfile::tempdir().unwrap();
    let runner = RecordingRunner::default();
    let helper = LinuxNetworkHelper::new(runner.clone(), directory.path().to_path_buf());
    let mut selected = request();
    selected.schema_version = 6;
    selected.routing = TunnelRoutingPolicy::selected_routes(
        ["198.51.100.0/24".to_owned(), "203.0.113.40/32".to_owned()],
        false,
    )
    .unwrap();

    let status = helper.connect(&selected).unwrap();
    assert_eq!(status.routing_mode, TunnelRoutingMode::SelectedRoutes);
    assert!(!status.ipv6_blocked);

    let commands = runner.commands.lock().unwrap();
    let wireguard = commands
        .iter()
        .find(|(program, arguments, _)| {
            program == "wg" && arguments.first().is_some_and(|value| value == "set")
        })
        .unwrap();
    let allowed_index = wireguard
        .1
        .iter()
        .position(|value| value == "allowed-ips")
        .unwrap();
    let allowed = &wireguard.1[allowed_index + 1];
    assert!(allowed.contains("10.77.0.1/32"));
    assert!(allowed.contains("198.51.100.0/24"));
    assert!(!allowed.contains("0.0.0.0/0"));
    assert!(commands.iter().any(|(program, arguments, _)| {
        program == "ip"
            && arguments
                == &[
                    "-4",
                    "route",
                    "add",
                    "198.51.100.0/24",
                    "dev",
                    INTERFACE_NAME,
                    "table",
                    ROUTING_TABLE,
                ]
    }));
    assert!(!commands.iter().any(|(program, arguments, _)| {
        program == "ip"
            && arguments
                .iter()
                .any(|value| value == "suppress_prefixlength")
    }));
    assert!(!commands.iter().any(|(program, arguments, input)| {
        program == "nft"
            && arguments == &["-f", "-"]
            && String::from_utf8_lossy(input).contains("sirinvpn_client6")
    }));
    assert!(commands.iter().any(|(program, arguments, _)| {
        program == "resolvectl" && arguments == &["domain", INTERFACE_NAME, "~."]
    }));
}

#[test]
fn local_network_exceptions_preserve_private_dns_and_clean_reserved_rules() {
    let directory = tempfile::tempdir().unwrap();
    let runner = RecordingRunner::default();
    let helper = LinuxNetworkHelper::new(runner.clone(), directory.path().to_path_buf());
    let mut routed = request();
    routed.schema_version = 6;
    routed.routing = TunnelRoutingPolicy::full_tunnel(true);

    helper.connect(&routed).unwrap();
    {
        let commands = runner.commands.lock().unwrap();
        assert!(commands.iter().any(|(program, arguments, _)| {
            program == "ip"
                && arguments
                    == &[
                        "-4",
                        "rule",
                        "add",
                        "to",
                        "10.77.0.1/32",
                        "table",
                        ROUTING_TABLE,
                        "priority",
                        DNS_RULE_PRIORITY,
                    ]
        }));
        assert!(commands.iter().any(|(program, arguments, _)| {
            program == "ip"
                && arguments
                    == &[
                        "-4",
                        "rule",
                        "add",
                        "to",
                        "192.168.0.0/16",
                        "table",
                        "main",
                        "priority",
                        "9993",
                    ]
        }));
        let ipv6_guard = commands
            .iter()
            .find(|(program, arguments, input)| {
                program == "nft"
                    && arguments == &["-f", "-"]
                    && String::from_utf8_lossy(input).contains("sirinvpn_client6")
            })
            .map(|(_, _, input)| String::from_utf8_lossy(input).into_owned())
            .unwrap();
        assert!(ipv6_guard.contains("ip6 daddr fe80::/10 accept"));
        assert!(ipv6_guard.contains("oifname != \"lo\" drop"));
    }

    helper.disconnect().unwrap();
    let commands = runner.commands.lock().unwrap();
    assert!(commands.iter().any(|(program, arguments, _)| {
        program == "ip"
            && arguments
                == &[
                    "-4",
                    "rule",
                    "delete",
                    "to",
                    "10.77.0.1/32",
                    "table",
                    ROUTING_TABLE,
                    "priority",
                    DNS_RULE_PRIORITY,
                ]
    }));
    assert!(commands.iter().any(|(program, arguments, _)| {
        program == "ip"
            && arguments
                == &[
                    "-6", "rule", "delete", "to", "ff00::/8", "table", "main", "priority", "9993",
                ]
    }));
}

#[test]
fn automatic_reconnect_candidates_are_bounded_unique_and_selected_first() {
    let key = STANDARD.encode([9_u8; 32]);
    let selections = vec![
        selection(TransportKind::DirectUdp, 51_820, None, 1_420),
        selection(TransportKind::ObfuscatedUdp, 443, Some(key.clone()), 1_320),
        TransportSelection {
            https: None,
            server_certificate_sha256: Some(STANDARD.encode([11_u8; 32])),
            ..selection(TransportKind::TlsLike, 443, Some(key.clone()), 1_280)
        },
        selection(TransportKind::TcpFallback, 443, Some(key.clone()), 1_280),
        selection(TransportKind::DirectUdp, 51_820, None, 1_420),
    ];

    let candidates = automatic_reconnect_candidates(&selections, TransportKind::ObfuscatedUdp);

    assert_eq!(candidates.len(), 3);
    assert_eq!(candidates[0].transport, TransportKind::ObfuscatedUdp);
    assert_eq!(candidates[1].transport, TransportKind::DirectUdp);
    assert_eq!(candidates[2].transport, TransportKind::TcpFallback);
    assert!(
        candidates
            .iter()
            .all(|candidate| candidate.transport != TransportKind::TlsLike)
    );
    assert!(automatic_reconnect_candidates(&selections[..1], TransportKind::DirectUdp).is_empty());
    assert!(
        automatic_reconnect_candidates(&selections, TransportKind::TcpFallback)
            .iter()
            .take(1)
            .all(|candidate| candidate.transport == TransportKind::TcpFallback)
    );
}

#[test]
fn reconnect_candidates_require_a_persistent_matching_unique_plan() {
    let valid = persistent_automatic_request();
    assert!(validate_request(&valid).is_ok());

    let mut transient = valid.clone();
    transient.persistent_protection = false;
    assert!(validate_request(&transient).is_err());

    let mut one_candidate = valid.clone();
    one_candidate.reconnect_candidates.truncate(1);
    assert!(validate_request(&one_candidate).is_err());

    let mut mismatched_first = valid.clone();
    mismatched_first.reconnect_candidates.swap(0, 1);
    assert!(validate_request(&mismatched_first).is_err());

    let mut duplicate = valid.clone();
    duplicate.reconnect_candidates[2] = duplicate.reconnect_candidates[1].clone();
    assert!(validate_request(&duplicate).is_err());

    let mut invalid_key = valid;
    invalid_key.reconnect_candidates[1].server_transport_public_key =
        Some(STANDARD.encode([0_u8; 32]));
    assert!(validate_request(&invalid_key).is_err());
}

#[test]
fn obfuscated_requests_require_schema_three_and_a_pinned_transport_key() {
    let mut request = request();
    request.transport = TransportKind::ObfuscatedUdp;
    assert!(validate_request(&request).is_err());

    request.schema_version = 3;
    request.server_transport_public_key = Some(STANDARD.encode([9_u8; 32]));
    request.endpoint_port = 443;
    request.mtu = 1_320;
    assert!(validate_request(&request).is_ok());

    let serialized = serde_json::to_value(&request).unwrap();
    assert_eq!(serialized["transport"], "obfuscated_udp");
    assert_eq!(
        serialized["server_transport_public_key"],
        STANDARD.encode([9_u8; 32])
    );
}

#[test]
fn tcp_requests_require_schema_four_and_a_pinned_transport_key() {
    let mut request = request();
    request.transport = TransportKind::TcpFallback;
    assert!(validate_request(&request).is_err());

    request.schema_version = 4;
    request.server_transport_public_key = Some(STANDARD.encode([9_u8; 32]));
    request.endpoint_port = 443;
    request.mtu = 1_280;
    assert!(validate_request(&request).is_ok());

    request.schema_version = 3;
    assert!(validate_request(&request).is_err());
}

#[test]
fn tls_like_requests_require_schema_five_two_pins_and_transient_mode() {
    let mut request = request();
    request.schema_version = 5;
    request.transport = TransportKind::TlsLike;
    request.endpoint_port = 443;
    request.mtu = 1_280;
    request.server_transport_public_key = Some(STANDARD.encode([9_u8; 32]));
    request.server_certificate_sha256 = Some(STANDARD.encode([10_u8; 32]));
    assert!(validate_request(&request).is_ok());

    let serialized = serde_json::to_value(&request).unwrap();
    assert_eq!(serialized["transport"], "tls_like");
    assert_eq!(
        serialized["server_certificate_sha256"],
        STANDARD.encode([10_u8; 32])
    );

    let mut missing_pin = request.clone();
    missing_pin.server_certificate_sha256 = None;
    assert!(validate_request(&missing_pin).is_err());

    let mut persistent = request;
    persistent.persistent_protection = true;
    assert!(validate_request(&persistent).is_err());
}

#[test]
fn obfuscated_transport_is_ready_before_wireguard_and_removed_on_disconnect() {
    let directory = tempfile::tempdir().unwrap();
    let runner = RecordingRunner::default();
    let helper = LinuxNetworkHelper::new(runner.clone(), directory.path().to_path_buf());
    let mut request = request();
    request.schema_version = 3;
    request.endpoint_port = 443;
    request.transport = TransportKind::ObfuscatedUdp;
    request.server_transport_public_key = Some(STANDARD.encode([9_u8; 32]));
    request.mtu = 1_320;

    let status = helper.connect(&request).unwrap();
    assert_eq!(status.transport, Some(TransportKind::ObfuscatedUdp));
    let transport_path = helper.carrier_config_path(TransportKind::ObfuscatedUdp);
    assert_eq!(
        fs::metadata(&transport_path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let config: ClientRelayConfig =
        serde_json::from_slice(&fs::read(&transport_path).unwrap()).unwrap();
    assert_eq!(config.server_address, "203.0.113.8:443".parse().unwrap());
    assert_eq!(config.socket_mark, Some(51_820));

    {
        let commands = runner.commands.lock().unwrap();
        let transport_start = commands
            .iter()
            .position(|(program, arguments, _)| {
                program == "systemctl"
                    && arguments == &["start", "sirinvpn-transport@obfuscated_udp.service"]
            })
            .unwrap();
        let interface_create = commands
            .iter()
            .position(|(program, arguments, _)| {
                program == "ip"
                    && arguments == &["link", "add", INTERFACE_NAME, "type", "wireguard"]
            })
            .unwrap();
        assert!(transport_start < interface_create);
        assert!(commands.iter().any(|(program, arguments, _)| {
            program == "wg"
                && arguments.windows(2).any(|pair| {
                    pair[0] == "endpoint" && pair[1] == format!("127.0.0.1:{CLIENT_RELAY_PORT}")
                })
        }));
    }

    helper.disconnect().unwrap();
    assert!(!transport_path.exists());
    assert!(
        runner
            .commands
            .lock()
            .unwrap()
            .iter()
            .any(|(program, arguments, _)| {
                program == "systemctl"
                    && arguments == &["stop", "sirinvpn-transport@obfuscated_udp.service"]
            })
    );
}
