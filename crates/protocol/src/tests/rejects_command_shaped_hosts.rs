use super::*;

#[test]
fn rejects_command_shaped_hosts() {
    assert!(validate_host("vpn.example").is_ok());
    assert!(validate_host("203.0.113.4").is_ok());
    assert!(validate_host("vpn.example; reboot").is_err());
    assert!(validate_host("vpn.example;reboot").is_err());
    assert!(validate_host("-oProxyCommand=bad").is_err());
}

#[test]
fn dns_over_tls_endpoints_are_strict_and_canonical() {
    let endpoint: DnsOverTlsEndpoint = " 1.1.1.1#ONE.ONE.ONE.ONE ".parse().unwrap();
    assert_eq!(endpoint.address, "1.1.1.1".parse::<IpAddr>().unwrap());
    assert_eq!(endpoint.authentication_name, "one.one.one.one");
    assert_eq!(endpoint.to_string(), "1.1.1.1#one.one.one.one");

    let ipv6: DnsOverTlsEndpoint = "2606:4700:4700::1111#one.one.one.one".parse().unwrap();
    assert_eq!(
        ipv6.address,
        "2606:4700:4700::1111".parse::<IpAddr>().unwrap()
    );
    assert!("resolver.example".parse::<DnsOverTlsEndpoint>().is_err());
    assert!(
        "127.0.0.1#resolver.example"
            .parse::<DnsOverTlsEndpoint>()
            .is_err()
    );
    assert!(
        "169.254.1.1#resolver.example"
            .parse::<DnsOverTlsEndpoint>()
            .is_err()
    );
    assert!(
        "fe80::1#resolver.example"
            .parse::<DnsOverTlsEndpoint>()
            .is_err()
    );
    assert!(
        "1.1.1.1#bad_name.example"
            .parse::<DnsOverTlsEndpoint>()
            .is_err()
    );
}

#[test]
fn dns_over_tls_policy_requires_one_or_two_unique_endpoints() {
    let endpoint: DnsOverTlsEndpoint = "1.1.1.1#one.one.one.one".parse().unwrap();
    assert!(validate_dns_upstream(&DnsUpstream::Recursive).is_ok());
    assert!(validate_dns_upstream(&DnsUpstream::DnsOverTls { endpoints: vec![] }).is_err());
    assert!(
        validate_dns_upstream(&DnsUpstream::DnsOverTls {
            endpoints: vec![endpoint.clone(), endpoint.clone()],
        })
        .is_err()
    );
    assert!(
        validate_dns_upstream(&DnsUpstream::DnsOverTls {
            endpoints: vec![endpoint.clone(), "1.0.0.1#one.one.one.one".parse().unwrap(),],
        })
        .is_ok()
    );
    assert!(
        validate_dns_upstream(&DnsUpstream::DnsOverTls {
            endpoints: vec![endpoint.clone(), endpoint.clone(), endpoint],
        })
        .is_err()
    );
}

#[test]
fn dns_over_https_endpoints_are_typed_canonical_and_bounded() {
    let endpoint: DnsOverHttpsEndpoint = "1.1.1.1#Cloudflare-DNS.com/dns-query".parse().unwrap();
    assert_eq!(endpoint.address, "1.1.1.1".parse::<IpAddr>().unwrap());
    assert_eq!(endpoint.authentication_name, "cloudflare-dns.com");
    assert_eq!(endpoint.path, "/dns-query");
    assert_eq!(endpoint.to_string(), "1.1.1.1#cloudflare-dns.com/dns-query");
    assert!(
        "2606:4700:4700::1111#cloudflare-dns.com/dns-query"
            .parse::<DnsOverHttpsEndpoint>()
            .is_ok()
    );
    for invalid in [
        "cloudflare-dns.com/dns-query",
        "1.1.1.1#cloudflare-dns.com",
        "1.1.1.1#cloudflare-dns.com/has?query",
        "1.1.1.1#bad_name.example/dns-query",
        "127.0.0.1#cloudflare-dns.com/dns-query",
        "240.0.0.1#cloudflare-dns.com/dns-query",
    ] {
        assert!(
            invalid.parse::<DnsOverHttpsEndpoint>().is_err(),
            "{invalid}"
        );
    }

    assert!(
        validate_dns_upstream(&DnsUpstream::DnsOverHttps {
            endpoints: vec![endpoint.clone()],
        })
        .is_ok()
    );
    assert!(validate_dns_upstream(&DnsUpstream::DnsOverHttps { endpoints: vec![] }).is_err());
    assert!(
        validate_dns_upstream(&DnsUpstream::DnsOverHttps {
            endpoints: vec![endpoint.clone(), endpoint.clone()],
        })
        .is_err()
    );
    assert!(
        validate_dns_upstream(&DnsUpstream::DnsOverHttps {
            endpoints: vec![
                endpoint,
                "1.0.0.1#cloudflare-dns.com/dns-query".parse().unwrap(),
                "9.9.9.9#dns.quad9.net/dns-query".parse().unwrap(),
            ],
        })
        .is_err()
    );
}

#[test]
fn private_dns_records_are_strict_canonical_and_bounded() {
    let ipv4: PrivateDnsRecord = " NAS.Home. = 10.20.30.40 ".parse().unwrap();
    assert_eq!(ipv4.name, "nas.home");
    assert_eq!(ipv4.address, "10.20.30.40".parse::<IpAddr>().unwrap());
    assert_eq!(ipv4.to_string(), "nas.home=10.20.30.40");

    let ipv6: PrivateDnsRecord = "server.home=fd00::10".parse().unwrap();
    assert_eq!(ipv6.address, "fd00::10".parse::<IpAddr>().unwrap());
    assert!("single-label=10.0.0.1".parse::<PrivateDnsRecord>().is_err());
    assert!(
        "bad_name.home=10.0.0.1"
            .parse::<PrivateDnsRecord>()
            .is_err()
    );
    assert!("host.home=127.0.0.1".parse::<PrivateDnsRecord>().is_err());
    assert!("host.home=0.0.0.1".parse::<PrivateDnsRecord>().is_err());
    assert!("host.home=240.0.0.1".parse::<PrivateDnsRecord>().is_err());
    assert!("host.home=fe80::1".parse::<PrivateDnsRecord>().is_err());
    assert!(
        "host.localhost=10.0.0.1"
            .parse::<PrivateDnsRecord>()
            .is_err()
    );

    assert!(validate_private_dns_records(&[ipv4.clone(), ipv6]).is_ok());
    assert!(validate_private_dns_records(&[ipv4.clone(), ipv4]).is_err());
    let too_many = (0..=MAX_PRIVATE_DNS_RECORDS)
        .map(|index| PrivateDnsRecord {
            name: format!("host-{index}.home"),
            address: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        })
        .collect::<Vec<_>>();
    assert!(validate_private_dns_records(&too_many).is_err());
}

#[test]
fn dns_feature_schemas_expand_and_contract_to_the_exact_policy_shape() {
    let records = vec!["nas.home=10.20.30.40".parse().unwrap()];
    let recursive = DnsUpstream::Recursive;
    let secure = DnsUpstream::DnsOverTls {
        endpoints: vec!["1.1.1.1#one.one.one.one".parse().unwrap()],
    };
    let https = DnsUpstream::DnsOverHttps {
        endpoints: vec!["1.1.1.1#cloudflare-dns.com/dns-query".parse().unwrap()],
    };

    assert_eq!(server_dns_configuration_schema_version(&recursive, &[]), 1);
    assert_eq!(server_dns_configuration_schema_version(&secure, &[]), 2);
    assert_eq!(server_dns_configuration_schema_version(&https, &[]), 4);
    assert_eq!(
        server_dns_configuration_schema_version(&recursive, &records),
        3
    );
    assert_eq!(
        server_dns_configuration_schema_version(&secure, &records),
        3
    );
    assert_eq!(server_dns_configuration_schema_version(&https, &records), 5);
    assert!(validate_server_dns_configuration(1, &recursive, &[]).is_ok());
    assert!(validate_server_dns_configuration(2, &secure, &[]).is_ok());
    assert!(validate_server_dns_configuration(3, &recursive, &records).is_ok());
    assert!(validate_server_dns_configuration(3, &secure, &records).is_ok());
    assert!(validate_server_dns_configuration(4, &https, &[]).is_ok());
    assert!(validate_server_dns_configuration(5, &https, &records).is_ok());
    assert!(validate_server_dns_configuration(1, &recursive, &records).is_err());
    assert!(validate_server_dns_configuration(2, &secure, &records).is_err());
    assert!(validate_server_dns_configuration(3, &recursive, &[]).is_err());
    assert!(validate_server_dns_configuration(3, &https, &records).is_err());
    assert!(validate_server_dns_configuration(4, &https, &records).is_err());
    assert!(validate_server_dns_configuration(5, &https, &[]).is_err());
}

#[test]
fn recursive_dns_keeps_legacy_json_while_dot_is_explicit() {
    let recursive = serde_json::to_value(DnsStatusFixture {
        dns_upstream: DnsUpstream::Recursive,
    })
    .unwrap();
    assert_eq!(recursive, serde_json::json!({}));

    let secure = serde_json::to_value(DnsStatusFixture {
        dns_upstream: DnsUpstream::DnsOverTls {
            endpoints: vec!["1.1.1.1#one.one.one.one".parse().unwrap()],
        },
    })
    .unwrap();
    assert_eq!(secure["dns_upstream"]["mode"], "dns_over_tls");
    assert_eq!(secure["dns_upstream"]["endpoints"][0]["address"], "1.1.1.1");

    let https = serde_json::to_value(DnsStatusFixture {
        dns_upstream: DnsUpstream::DnsOverHttps {
            endpoints: vec!["1.1.1.1#cloudflare-dns.com/dns-query".parse().unwrap()],
        },
    })
    .unwrap();
    assert_eq!(https["dns_upstream"]["mode"], "dns_over_https");
    assert_eq!(https["dns_upstream"]["endpoints"][0]["path"], "/dns-query");
}

#[test]
fn api_envelope_is_versioned() {
    let envelope = ApiEnvelope::new("ok");
    assert_eq!(envelope.api_version, API_VERSION);
    assert_ne!(envelope.request_id, Uuid::nil());
}

#[test]
fn ipv6_tunnel_addresses_are_stable_and_follow_ipv4_host_ids() {
    let server_id: ServerId = "12345678-1234-4678-9234-567812345678".parse().unwrap();

    assert_eq!(
        ipv6_tunnel_prefix(server_id),
        "fd12:3456:7812::".parse::<Ipv6Addr>().unwrap()
    );
    assert_eq!(ipv6_tunnel_cidr(server_id), "fd12:3456:7812::/64");
    assert_eq!(
        ipv6_tunnel_address(server_id, Ipv4Addr::new(10, 77, 0, 1)),
        Some("fd12:3456:7812::1".parse::<Ipv6Addr>().unwrap())
    );
    assert_eq!(
        ipv6_tunnel_address(server_id, Ipv4Addr::new(10, 77, 0, 254)),
        Some("fd12:3456:7812::fe".parse::<Ipv6Addr>().unwrap())
    );
    assert_eq!(
        ipv6_tunnel_address(server_id, Ipv4Addr::new(10, 77, 0, 0)),
        None
    );
    assert_eq!(
        ipv6_tunnel_address(server_id, Ipv4Addr::new(10, 78, 0, 2)),
        None
    );
}

#[test]
fn schema_one_owner_profiles_without_membership_ids_remain_compatible() {
    let id = ServerId::new();
    let profile: ServerProfile = serde_json::from_value(serde_json::json!({
        "schema_version": 1,
        "id": id,
        "name": "Legacy owner",
        "endpoint": { "host": "203.0.113.4", "wireguard_port": 51820 },
        "client_tunnel_address": "10.77.0.2",
        "server_tunnel_address": "10.77.0.1",
        "server_wireguard_public_key": "legacy-public-key",
        "pinned_server_certificate_pem": "legacy-server-certificate",
        "client_management_certificate_pem": "legacy-client-certificate",
        "identity_reference": "legacy-identity",
        "role": "owner"
    }))
    .unwrap();
    assert_eq!(profile.id, id);
    assert_eq!(profile.member_id, None);
    assert_eq!(profile.device_id, None);
    assert_eq!(profile.role, ServerRole::Owner);
    assert!(!profile.administrator);
    assert!(!profile.ipv6_tunnel_enabled);
}

#[test]
fn defaulted_p1b2_fields_do_not_change_legacy_profile_shape() {
    let profile: ServerProfile = serde_json::from_value(serde_json::json!({
        "schema_version": 1,
        "id": ServerId::new(),
        "name": "Legacy owner",
        "endpoint": { "host": "203.0.113.4", "wireguard_port": 51820 },
        "client_tunnel_address": "10.77.0.2",
        "server_tunnel_address": "10.77.0.1",
        "server_wireguard_public_key": "legacy-public-key",
        "pinned_server_certificate_pem": "legacy-server-certificate",
        "client_management_certificate_pem": "legacy-client-certificate",
        "identity_reference": "legacy-identity",
        "role": "owner"
    }))
    .unwrap();
    let serialized = serde_json::to_value(profile).unwrap();
    assert!(serialized.get("administrator").is_none());
    assert!(serialized.get("ipv6_tunnel_enabled").is_none());
}

#[test]
fn enrollment_results_default_ipv6_off_and_only_emit_it_when_enabled() {
    let legacy = serde_json::json!({
        "server_id": ServerId::new(),
        "member_id": MemberId::new(),
        "device_id": DeviceId::new(),
        "role": "member",
        "administrator": false,
        "server_name": "Legacy server",
        "endpoint": { "host": "203.0.113.4", "wireguard_port": 51820 },
        "client_tunnel_address": "10.77.0.3",
        "server_tunnel_address": "10.77.0.1",
        "server_wireguard_public_key": "server-key",
        "pinned_server_certificate_pem": "server-certificate"
    });
    let mut result: EnrollmentResult = serde_json::from_value(legacy).unwrap();
    assert!(!result.ipv6_tunnel_enabled);
    assert!(
        serde_json::to_value(&result)
            .unwrap()
            .get("ipv6_tunnel_enabled")
            .is_none()
    );

    result.ipv6_tunnel_enabled = true;
    assert_eq!(
        serde_json::to_value(result).unwrap()["ipv6_tunnel_enabled"],
        true
    );
}

#[test]
fn schema_one_status_without_live_access_fields_remains_compatible() {
    let status: ServerStatus = serde_json::from_value(serde_json::json!({
        "api_version": "v1",
        "server_name": "Legacy server",
        "connection_state": "connected",
        "interface_up": true,
        "dns_healthy": true,
        "transport": "direct_udp",
        "peer_count": 1,
        "rx_bytes": 12,
        "tx_bytes": 34,
        "uptime_seconds": 56
    }))
    .unwrap();
    assert_eq!(status.cpu_usage_basis_points, None);
    assert_eq!(status.memory_used_bytes, None);
    assert_eq!(status.memory_total_bytes, None);
    assert_eq!(status.rx_bytes_per_second, None);
    assert_eq!(status.tx_bytes_per_second, None);
    assert_eq!(status.caller_role, None);
    assert!(!status.caller_administrator);
    assert_eq!(status.caller_device_id, None);
    assert!(status.caller_identity_fingerprint.is_empty());
    assert_eq!(status.transport, TransportKind::DirectUdp);
    assert_eq!(status.dns_upstream, DnsUpstream::Recursive);
    assert!(status.private_dns_records.is_empty());
    let serialized = serde_json::to_value(status).unwrap();
    assert_eq!(serialized["transport"], "direct_udp");
    assert!(serialized.get("cpu_usage_basis_points").is_none());
    assert!(serialized.get("memory_used_bytes").is_none());
    assert!(serialized.get("memory_total_bytes").is_none());
    assert!(serialized.get("rx_bytes_per_second").is_none());
    assert!(serialized.get("tx_bytes_per_second").is_none());
    assert!(serialized.get("caller_role").is_none());
    assert!(serialized.get("caller_administrator").is_none());
    assert!(serialized.get("caller_device_id").is_none());
    assert!(serialized.get("caller_identity_fingerprint").is_none());
    assert!(serialized.get("dns_upstream").is_none());
    assert!(serialized.get("private_dns_records").is_none());
}

#[test]
fn transport_kind_accepts_the_implemented_authenticated_wire_values() {
    assert_eq!(
        serde_json::from_str::<TransportKind>(r#""obfuscated_udp""#).unwrap(),
        TransportKind::ObfuscatedUdp
    );
    assert_eq!(
        serde_json::from_str::<TransportKind>(r#""tcp_fallback""#).unwrap(),
        TransportKind::TcpFallback
    );
    assert_eq!(
        serde_json::from_str::<TransportKind>(r#""tls_like""#).unwrap(),
        TransportKind::TlsLike
    );
}

#[test]
fn local_transport_preference_defaults_to_automatic_and_resolves_manual_modes() {
    assert_eq!(
        TransportPreference::default(),
        TransportPreference::Automatic
    );
    assert_eq!(
        serde_json::from_str::<TransportPreference>(r#""automatic""#).unwrap(),
        TransportPreference::Automatic
    );
    assert_eq!(
        TransportPreference::DirectUdp.concrete_kind(),
        Some(TransportKind::DirectUdp)
    );
    assert_eq!(
        TransportPreference::ObfuscatedUdp.concrete_kind(),
        Some(TransportKind::ObfuscatedUdp)
    );
    assert_eq!(
        TransportPreference::TlsLike.concrete_kind(),
        Some(TransportKind::TlsLike)
    );
    assert_eq!(
        TransportPreference::TcpFallback.concrete_kind(),
        Some(TransportKind::TcpFallback)
    );
    assert_eq!(TransportPreference::Automatic.concrete_kind(), None);
}

#[test]
fn local_network_profiles_are_stable_and_default_to_automatic() {
    assert_eq!(NetworkProfile::default(), NetworkProfile::Automatic);
    for (encoded, expected) in [
        (r#""automatic""#, NetworkProfile::Automatic),
        (r#""normal""#, NetworkProfile::Normal),
        (r#""restricted""#, NetworkProfile::Restricted),
        (r#""extreme""#, NetworkProfile::Extreme),
    ] {
        assert_eq!(
            serde_json::from_str::<NetworkProfile>(encoded).unwrap(),
            expected
        );
    }
    assert!(serde_json::from_str::<NetworkProfile>(r#""adaptive""#).is_err());
}
