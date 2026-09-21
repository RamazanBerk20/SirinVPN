use super::*;

#[test]
fn dns_policy_migration_is_reversible_and_preserves_server_identity() {
    let directory = tempfile::tempdir().unwrap();
    let paths = ServerPaths::under(directory.path());
    let owner = LocalIdentity::generate("Owner").unwrap();
    let server_id = ServerId::new();
    let original = initialize(
        &paths,
        "DNS migration target",
        &owner.public.management_certificate_pem,
        server_id,
        &owner.public.wireguard_public_key,
        51_820,
    )
    .unwrap();
    let wireguard_key = fs::read(&paths.wireguard_private_key).unwrap();
    let tls_key = fs::read(&paths.tls_private_key).unwrap();
    let authorization = fs::read(&paths.authorization).unwrap();
    let secure_dns = DnsUpstream::DnsOverTls {
        endpoints: vec!["1.1.1.1#one.one.one.one".parse().unwrap()],
    };

    let migrated = initialize_with_transport_capabilities(
        &paths,
        "DNS migration target",
        &owner.public.management_certificate_pem,
        server_id,
        &owner.public.wireguard_public_key,
        51_820,
        ServerCapabilities {
            public_host: None,
            previous_public_host: None,
            alternate_endpoint_hosts: None,
            ipv6_tunnel_enabled: None,
            obfuscated_udp_port: None,
            tcp_fallback_port: None,
            https: None,
            https_certificate: None,
            update_transport_ports: false,
            disable_https: false,
            tls_like_port: None,
            dns_upstream: Some(secure_dns.clone()),
            private_dns_records: None,
        },
    )
    .unwrap();
    assert_eq!(migrated.dns_upstream, secure_dns);
    assert_eq!(migrated.wireguard_public_key, original.wireguard_public_key);
    let configuration = load_configuration(&paths).unwrap();
    assert_eq!(configuration.schema_version, 2);
    assert_eq!(configuration.dns_upstream, secure_dns);
    assert_eq!(
        fs::read(&paths.wireguard_private_key).unwrap(),
        wireguard_key
    );
    assert_eq!(fs::read(&paths.tls_private_key).unwrap(), tls_key);
    assert_eq!(fs::read(&paths.authorization).unwrap(), authorization);

    let private_dns_records = vec![
        "nas.home=10.20.30.40".parse().unwrap(),
        "server.home=fd00::10".parse().unwrap(),
    ];
    let records_migrated = initialize_with_transport_capabilities(
        &paths,
        "DNS migration target",
        &owner.public.management_certificate_pem,
        server_id,
        &owner.public.wireguard_public_key,
        51_820,
        ServerCapabilities {
            private_dns_records: Some(private_dns_records.clone()),
            ..ServerCapabilities::default()
        },
    )
    .unwrap();
    assert_eq!(records_migrated.dns_upstream, secure_dns);
    assert_eq!(records_migrated.private_dns_records, private_dns_records);
    let configuration = load_configuration(&paths).unwrap();
    assert_eq!(configuration.schema_version, 3);
    assert_eq!(configuration.dns_upstream, secure_dns);
    assert_eq!(configuration.private_dns_records, private_dns_records);

    let preserved = initialize_with_transport_capabilities(
        &paths,
        "DNS migration target",
        &owner.public.management_certificate_pem,
        server_id,
        &owner.public.wireguard_public_key,
        51_820,
        ServerCapabilities::default(),
    )
    .unwrap();
    assert_eq!(preserved.dns_upstream, secure_dns);
    assert_eq!(preserved.private_dns_records, private_dns_records);

    let rolled_back = initialize_with_transport_capabilities(
        &paths,
        "DNS migration target",
        &owner.public.management_certificate_pem,
        server_id,
        &owner.public.wireguard_public_key,
        51_820,
        ServerCapabilities {
            dns_upstream: Some(DnsUpstream::Recursive),
            ..ServerCapabilities::default()
        },
    )
    .unwrap();
    assert_eq!(rolled_back.dns_upstream, DnsUpstream::Recursive);
    assert_eq!(rolled_back.private_dns_records, private_dns_records);
    let configuration = load_configuration(&paths).unwrap();
    assert_eq!(configuration.schema_version, 3);
    assert_eq!(configuration.dns_upstream, DnsUpstream::Recursive);
    assert_eq!(configuration.private_dns_records, private_dns_records);

    let records_cleared = initialize_with_transport_capabilities(
        &paths,
        "DNS migration target",
        &owner.public.management_certificate_pem,
        server_id,
        &owner.public.wireguard_public_key,
        51_820,
        ServerCapabilities {
            private_dns_records: Some(Vec::new()),
            ..ServerCapabilities::default()
        },
    )
    .unwrap();
    assert_eq!(records_cleared.private_dns_records, Vec::new());
    let configuration = load_configuration(&paths).unwrap();
    assert_eq!(configuration.schema_version, 1);
    assert_eq!(configuration.dns_upstream, DnsUpstream::Recursive);
    assert!(configuration.private_dns_records.is_empty());

    let https_dns = DnsUpstream::DnsOverHttps {
        endpoints: vec!["1.1.1.1#cloudflare-dns.com/dns-query".parse().unwrap()],
    };
    let https_migrated = initialize_with_transport_capabilities(
        &paths,
        "DNS migration target",
        &owner.public.management_certificate_pem,
        server_id,
        &owner.public.wireguard_public_key,
        51_820,
        ServerCapabilities {
            dns_upstream: Some(https_dns.clone()),
            ..ServerCapabilities::default()
        },
    )
    .unwrap();
    assert_eq!(https_migrated.dns_upstream, https_dns);
    assert_eq!(load_configuration(&paths).unwrap().schema_version, 4);

    let https_records_migrated = initialize_with_transport_capabilities(
        &paths,
        "DNS migration target",
        &owner.public.management_certificate_pem,
        server_id,
        &owner.public.wireguard_public_key,
        51_820,
        ServerCapabilities {
            private_dns_records: Some(private_dns_records.clone()),
            ..ServerCapabilities::default()
        },
    )
    .unwrap();
    assert_eq!(https_records_migrated.dns_upstream, https_dns);
    assert_eq!(
        https_records_migrated.private_dns_records,
        private_dns_records
    );
    assert_eq!(load_configuration(&paths).unwrap().schema_version, 5);

    let https_preserved = initialize_with_transport_capabilities(
        &paths,
        "DNS migration target",
        &owner.public.management_certificate_pem,
        server_id,
        &owner.public.wireguard_public_key,
        51_820,
        ServerCapabilities::default(),
    )
    .unwrap();
    assert_eq!(https_preserved.dns_upstream, https_dns);
    assert_eq!(https_preserved.private_dns_records, private_dns_records);

    let tls_restored = initialize_with_transport_capabilities(
        &paths,
        "DNS migration target",
        &owner.public.management_certificate_pem,
        server_id,
        &owner.public.wireguard_public_key,
        51_820,
        ServerCapabilities {
            dns_upstream: Some(secure_dns.clone()),
            ..ServerCapabilities::default()
        },
    )
    .unwrap();
    assert_eq!(tls_restored.dns_upstream, secure_dns);
    assert_eq!(load_configuration(&paths).unwrap().schema_version, 3);

    initialize_with_transport_capabilities(
        &paths,
        "DNS migration target",
        &owner.public.management_certificate_pem,
        server_id,
        &owner.public.wireguard_public_key,
        51_820,
        ServerCapabilities {
            private_dns_records: Some(Vec::new()),
            ..ServerCapabilities::default()
        },
    )
    .unwrap();
    assert_eq!(load_configuration(&paths).unwrap().schema_version, 2);

    initialize_with_transport_capabilities(
        &paths,
        "DNS migration target",
        &owner.public.management_certificate_pem,
        server_id,
        &owner.public.wireguard_public_key,
        51_820,
        ServerCapabilities {
            dns_upstream: Some(DnsUpstream::Recursive),
            ..ServerCapabilities::default()
        },
    )
    .unwrap();
    let configuration = load_configuration(&paths).unwrap();
    assert_eq!(configuration.schema_version, 1);
    assert_eq!(
        fs::read(&paths.wireguard_private_key).unwrap(),
        wireguard_key
    );
    assert_eq!(fs::read(&paths.tls_private_key).unwrap(), tls_key);
    assert_eq!(fs::read(&paths.authorization).unwrap(), authorization);

    let mut inconsistent = serde_json::to_value(configuration).unwrap();
    inconsistent["schema_version"] = serde_json::json!(2);
    fs::write(
        &paths.configuration,
        serde_json::to_vec_pretty(&inconsistent).unwrap(),
    )
    .unwrap();
    assert!(load_configuration(&paths).is_err());
}

#[test]
fn wireguard_peer_routes_include_the_stable_ipv6_host_only_when_enabled() {
    let server_id: ServerId = "12345678-1234-4678-9234-567812345678".parse().unwrap();
    let address = Ipv4Addr::new(10, 77, 0, 7);
    assert_eq!(
        peer_allowed_ips(server_id, address, false).unwrap(),
        "10.77.0.7/32"
    );
    assert_eq!(
        peer_allowed_ips(server_id, address, true).unwrap(),
        "10.77.0.7/32,fd12:3456:7812::7/128"
    );
    assert!(peer_allowed_ips(server_id, Ipv4Addr::new(192, 0, 2, 7), true).is_err());
}

#[test]
fn peer_isolation_policy_contains_only_explicitly_enabled_devices() {
    let directory = tempfile::tempdir().unwrap();
    let paths = ServerPaths::under(directory.path());
    let owner = LocalIdentity::generate("Owner").unwrap();
    let server_id: ServerId = "12345678-1234-4678-9234-567812345678".parse().unwrap();
    initialize(
        &paths,
        "Test",
        &owner.public.management_certificate_pem,
        server_id,
        &owner.public.wireguard_public_key,
        51_820,
    )
    .unwrap();
    let mut configuration = load_configuration(&paths).unwrap();
    let mut authorization = load_authorization(&paths.authorization).unwrap();

    let isolated = peer_isolation_state(&configuration, &authorization).unwrap();
    assert_eq!(isolated, PeerIsolationState::default());
    assert_eq!(
        peer_isolation_nft_batch(&isolated),
        concat!(
            "flush set inet sirinvpn_filter peer_communication4\n",
            "flush set inet sirinvpn_filter peer_communication6\n",
        )
    );

    authorization.devices[0].peer_communication_enabled = true;
    configuration.ipv6_tunnel_enabled = true;
    let enabled = peer_isolation_state(&configuration, &authorization).unwrap();
    assert_eq!(enabled.ipv4, vec![Ipv4Addr::new(10, 77, 0, 2)]);
    assert_eq!(
        enabled.ipv6,
        vec!["fd12:3456:7812::2".parse::<Ipv6Addr>().unwrap()]
    );
    let batch = peer_isolation_nft_batch(&enabled);
    assert!(batch.contains("peer_communication4 { 10.77.0.2 }"));
    assert!(batch.contains("peer_communication6 { fd12:3456:7812::2 }"));
}

#[test]
fn port_forward_policy_is_exact_revocable_and_reserves_control_ports() {
    let directory = tempfile::tempdir().unwrap();
    let paths = ServerPaths::under(directory.path());
    let owner = LocalIdentity::generate("Owner").unwrap();
    initialize(
        &paths,
        "Test",
        &owner.public.management_certificate_pem,
        ServerId::new(),
        &owner.public.wireguard_public_key,
        51_820,
    )
    .unwrap();
    let configuration = load_configuration(&paths).unwrap();
    let mut authorization = load_authorization(&paths.authorization).unwrap();
    let operational = OperationalConfiguration {
        schema_version: OPERATIONAL_CONFIGURATION_SCHEMA_VERSION,
        external_interface: "eth0".to_owned(),
        ssh_port: 22,
    };
    assert!(
        port_forward_nft_batch(&configuration, None, &authorization)
            .unwrap()
            .is_none()
    );
    let empty = port_forward_nft_batch(&configuration, Some(&operational), &authorization)
        .unwrap()
        .unwrap();
    assert_eq!(
        empty,
        concat!(
            "flush chain inet sirinvpn_filter port_forward\n",
            "flush chain ip sirinvpn_nat port_forward_prerouting\n",
        )
    );

    authorization
        .add_port_forward(PortForward {
            protocol: PortForwardProtocol::Tcp,
            public_port: 48_080,
            device_id: authorization.devices[0].id,
            device_port: 8_080,
        })
        .unwrap();
    let batch = port_forward_nft_batch(&configuration, Some(&operational), &authorization)
        .unwrap()
        .unwrap();
    assert!(batch.contains(
        "iifname \"eth0\" tcp dport 48080 ct mark set 0x5356504e dnat to 10.77.0.2:8080"
    ));
    assert!(batch.contains(
        "ct mark 0x5356504e ip daddr 10.77.0.2 tcp dport 8080 ct original proto-dst 48080 meta mark set 0x5356504e accept"
    ));
    assert!(port_forward_nft_batch(&configuration, None, &authorization).is_err());

    let mut reserved = authorization.port_forwards[0].clone();
    reserved.protocol = PortForwardProtocol::Udp;
    reserved.public_port = configuration.wireguard_port;
    assert!(validate_port_forward(&configuration, &operational, &reserved).is_err());
    reserved.protocol = PortForwardProtocol::Tcp;
    reserved.public_port = configuration.management_port;
    assert!(validate_port_forward(&configuration, &operational, &reserved).is_err());
    reserved.protocol = PortForwardProtocol::Udp;
    reserved.public_port = DOH_PROXY_PORT;
    assert!(validate_port_forward(&configuration, &operational, &reserved).is_err());
}

#[test]
fn operational_configuration_rejects_unsafe_interface_names() {
    assert!(is_safe_interface_name("ens192"));
    assert!(is_safe_interface_name("enp0s3.20"));
    assert!(!is_safe_interface_name(""));
    assert!(!is_safe_interface_name("eth0;reboot"));
    assert!(!is_safe_interface_name("interface-name-is-too-long"));

    let directory = tempfile::tempdir().unwrap();
    let paths = ServerPaths::under(directory.path());
    fs::write(
        &paths.operational_configuration,
        br#"{"schema_version":1,"external_interface":"eth0","ssh_port":22}"#,
    )
    .unwrap();
    fs::set_permissions(
        &paths.operational_configuration,
        fs::Permissions::from_mode(0o666),
    )
    .unwrap();
    assert!(load_operational_configuration(&paths).is_err());
}

#[test]
fn proc_ipv6_parser_requires_a_ula_on_the_named_interface() {
    let interfaces = concat!(
        "fd123456781200000000000000000001 02 40 00 80 sirinvpn0\n",
        "20010db8000000000000000000000001 03 40 00 80 eth0\n",
        "fd123456781200000000000000000002 04 40 00 80 other0\n",
    );
    assert!(interface_list_has_private_ipv6(interfaces, "sirinvpn0"));
    assert!(!interface_list_has_private_ipv6(interfaces, "eth0"));
    assert!(!interface_list_has_private_ipv6(interfaces, "missing"));
    assert!(!interface_list_has_private_ipv6("malformed", "sirinvpn0"));
}

#[test]
fn state_validation_rejects_key_mismatches_and_future_authorization() {
    let directory = tempfile::tempdir().unwrap();
    let paths = ServerPaths::under(directory.path().join("current"));
    let owner = LocalIdentity::generate("Owner").unwrap();
    let server_id = ServerId::new();
    initialize(
        &paths,
        "Validation target",
        &owner.public.management_certificate_pem,
        server_id,
        &owner.public.wireguard_public_key,
        51_820,
    )
    .unwrap();
    validate_state(&paths).unwrap();

    let wireguard_private_key = fs::read(&paths.wireguard_private_key).unwrap();
    let other_device = LocalIdentity::generate("Other device").unwrap();
    fs::write(
        &paths.wireguard_private_key,
        other_device.secret.wireguard_private_key.as_bytes(),
    )
    .unwrap();
    assert!(validate_state(&paths).is_err());
    fs::write(&paths.wireguard_private_key, wireguard_private_key).unwrap();

    let tls_private_key = fs::read(&paths.tls_private_key).unwrap();
    let other_paths = ServerPaths::under(directory.path().join("other"));
    initialize(
        &other_paths,
        "Other server",
        &owner.public.management_certificate_pem,
        ServerId::new(),
        &owner.public.wireguard_public_key,
        51_820,
    )
    .unwrap();
    fs::copy(&other_paths.tls_private_key, &paths.tls_private_key).unwrap();
    assert!(validate_state(&paths).is_err());
    fs::write(&paths.tls_private_key, tls_private_key).unwrap();

    let mut authorization: serde_json::Value =
        serde_json::from_slice(&fs::read(&paths.authorization).unwrap()).unwrap();
    authorization["schema_version"] = serde_json::json!(2);
    fs::write(
        &paths.authorization,
        serde_json::to_vec(&authorization).unwrap(),
    )
    .unwrap();
    assert!(validate_state(&paths).is_err());

    fs::remove_file(&paths.authorization).unwrap();
    assert!(validate_state(&paths).is_err());
    assert!(
        initialize(
            &paths,
            "Validation target",
            &owner.public.management_certificate_pem,
            server_id,
            &owner.public.wireguard_public_key,
            51_820,
        )
        .is_err()
    );
    assert!(!paths.authorization.exists());
}
