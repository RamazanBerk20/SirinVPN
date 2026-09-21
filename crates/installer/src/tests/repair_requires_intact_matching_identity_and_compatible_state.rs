use super::*;

#[test]
fn repair_requires_intact_matching_identity_and_compatible_state() {
    let owner = LocalIdentity::generate("Current owner").unwrap();
    let previous_owner = LocalIdentity::generate("Previous owner").unwrap();
    let server = LocalIdentity::generate("Server").unwrap();
    let server_id = ServerId::new();
    let owner_member_id = MemberId::new();
    let profile = ServerProfile {
        favorite: false,
        schema_version: 1,
        id: server_id,
        name: "Repair target".to_owned(),
        endpoint: ServerEndpoint {
            host: "203.0.113.9".to_owned(),
            wireguard_port: 51_820,
        },
        endpoint_generation: 0,
        pending_previous_endpoint: None,
        pending_previous_transports: None,
        endpoint_discovery_port: None,
        alternate_endpoint_hosts: Vec::new(),
        client_tunnel_address: "10.77.0.9".parse().unwrap(),
        server_tunnel_address: SERVER_TUNNEL_ADDRESS.parse().unwrap(),
        ipv6_tunnel_enabled: false,
        server_wireguard_public_key: server.public.wireguard_public_key.clone(),
        pinned_server_certificate_pem: server.public.management_certificate_pem.clone(),
        client_management_certificate_pem: owner.public.management_certificate_pem.clone(),
        identity_reference: server_id.to_string(),
        role: ServerRole::Owner,
        administrator: false,
        member_id: Some(MemberId::new()),
        device_id: Some(sirinvpn_protocol::DeviceId::new()),
        obfuscated_udp: None,
        tcp_fallback: None,
        tls_like: None,
    };
    let request = RepairRequest {
        transport: None,
        profile: profile.clone(),
        target: SshTarget {
            host: profile.endpoint.host.clone(),
            port: 22,
            username: "root".to_owned(),
            authentication: SshAuthentication::Agent,
            sudo_password: None,
            expected_host_key_sha256: Some("SHA256:test".to_owned()),
        },
        server_binary: "/tmp/server".into(),
        identity: owner.public.clone(),
        dns_upstream: None,
        private_dns_records: None,
    };
    assert!(validate_repair_request(&request).is_ok());

    let configuration = serde_json::json!({
        "schema_version": 1,
        "server_name": "Remote name",
        "interface_name": INTERFACE_NAME,
        "tunnel_cidr": TUNNEL_CIDR,
        "server_tunnel_address": SERVER_TUNNEL_ADDRESS,
        "wireguard_port": 51_820,
        "management_port": DEFAULT_MANAGEMENT_PORT,
        "wireguard_public_key": server.public.wireguard_public_key,
        "owner_certificate_pem": previous_owner.public.management_certificate_pem,
    });
    let authorization = serde_json::json!({
        "schema_version": 1,
        "server_id": server_id,
        "members": [{
            "id": owner_member_id,
            "name": "Current owner",
            "role": "owner"
        }],
        "devices": [{
            "member_id": owner_member_id,
            "wireguard_public_key": owner.public.wireguard_public_key,
            "management_certificate_pem": owner.public.management_certificate_pem
        }]
    });
    assert_eq!(
        repair_identity_check(
            &configuration.to_string(),
            &authorization.to_string(),
            &profile.pinned_server_certificate_pem,
            &request.profile,
            &request.identity,
        ),
        RepairIdentityCheck::Match
    );

    let mut future_configuration = configuration.clone();
    future_configuration["schema_version"] = serde_json::json!(2);
    assert_eq!(
        repair_identity_check(
            &future_configuration.to_string(),
            &authorization.to_string(),
            &profile.pinned_server_certificate_pem,
            &request.profile,
            &request.identity,
        ),
        RepairIdentityCheck::Incompatible
    );
    let mut secure_configuration = configuration.clone();
    secure_configuration["schema_version"] = serde_json::json!(2);
    secure_configuration["dns_upstream"] = serde_json::json!({
        "mode": "dns_over_tls",
        "endpoints": [{
            "address": "1.1.1.1",
            "authentication_name": "one.one.one.one"
        }]
    });
    assert_eq!(
        repair_identity_check(
            &secure_configuration.to_string(),
            &authorization.to_string(),
            &profile.pinned_server_certificate_pem,
            &request.profile,
            &request.identity,
        ),
        RepairIdentityCheck::Match
    );
    let mut https_configuration = configuration.clone();
    https_configuration["schema_version"] = serde_json::json!(4);
    https_configuration["dns_upstream"] = serde_json::json!({
        "mode": "dns_over_https",
        "endpoints": [{
            "address": "1.1.1.1",
            "authentication_name": "cloudflare-dns.com",
            "path": "/dns-query"
        }]
    });
    assert_eq!(
        repair_identity_check(
            &https_configuration.to_string(),
            &authorization.to_string(),
            &profile.pinned_server_certificate_pem,
            &request.profile,
            &request.identity,
        ),
        RepairIdentityCheck::Match
    );
    https_configuration["schema_version"] = serde_json::json!(5);
    https_configuration["private_dns_records"] = serde_json::json!([{
        "name": "nas.home",
        "address": "10.20.30.40"
    }]);
    assert_eq!(
        repair_identity_check(
            &https_configuration.to_string(),
            &authorization.to_string(),
            &profile.pinned_server_certificate_pem,
            &request.profile,
            &request.identity,
        ),
        RepairIdentityCheck::Match
    );
    let mut suspended_authorization = authorization.clone();
    suspended_authorization["schema_version"] = serde_json::json!(2);
    suspended_authorization["members"]
        .as_array_mut()
        .unwrap()
        .push(serde_json::json!({
            "id": MemberId::new(), "name": "Suspended member", "role": "member", "suspended": true
        }));
    assert_eq!(
        repair_identity_check(
            &configuration.to_string(),
            &suspended_authorization.to_string(),
            &profile.pinned_server_certificate_pem,
            &request.profile,
            &request.identity
        ),
        RepairIdentityCheck::Match
    );
    assert!(uninstall_identity_matches(
        &configuration.to_string(),
        &suspended_authorization.to_string(),
        server_id,
        &request.identity.management_certificate_pem
    ));
    suspended_authorization["schema_version"] = serde_json::json!(1);
    assert_ne!(
        repair_identity_check(
            &configuration.to_string(),
            &suspended_authorization.to_string(),
            &profile.pinned_server_certificate_pem,
            &request.profile,
            &request.identity
        ),
        RepairIdentityCheck::Match
    );
    suspended_authorization["schema_version"] = serde_json::json!(2);
    suspended_authorization["members"][0]["suspended"] = serde_json::json!(true);
    assert_ne!(
        repair_identity_check(
            &configuration.to_string(),
            &suspended_authorization.to_string(),
            &profile.pinned_server_certificate_pem,
            &request.profile,
            &request.identity
        ),
        RepairIdentityCheck::Match
    );
    let mut future_authorization = authorization.clone();
    future_authorization["schema_version"] = serde_json::json!(6);
    assert_eq!(
        repair_identity_check(
            &configuration.to_string(),
            &future_authorization.to_string(),
            &profile.pinned_server_certificate_pem,
            &request.profile,
            &request.identity,
        ),
        RepairIdentityCheck::Incompatible
    );
    assert_eq!(
        repair_identity_check(
            &configuration.to_string(),
            &authorization.to_string(),
            "different server certificate",
            &request.profile,
            &request.identity,
        ),
        RepairIdentityCheck::Mismatch
    );

    let mut legacy_configuration = configuration;
    legacy_configuration["owner_certificate_pem"] =
        serde_json::json!(request.identity.management_certificate_pem);
    assert_eq!(
        repair_identity_check(
            &legacy_configuration.to_string(),
            "",
            &profile.pinned_server_certificate_pem,
            &request.profile,
            &request.identity,
        ),
        RepairIdentityCheck::Match
    );
    let bootstrap = BootstrapOutput {
        endpoint_transition: None,
        wireguard_public_key: profile.server_wireguard_public_key.clone(),
        management_certificate_pem: profile.pinned_server_certificate_pem.clone(),
        server_tunnel_address: profile.server_tunnel_address,
        wireguard_port: profile.endpoint.wireguard_port,
        management_port: DEFAULT_MANAGEMENT_PORT,
        dns_upstream: DnsUpstream::Recursive,
        private_dns_records: Vec::new(),
        ipv6_tunnel_enabled: false,
        obfuscated_udp: Some(ObfuscatedUdpEndpoint {
            port: DEFAULT_OBFUSCATED_UDP_PORT,
            server_public_key: STANDARD.encode([9_u8; 32]),
        }),
        tcp_fallback: Some(TcpFallbackEndpoint {
            port: DEFAULT_TCP_FALLBACK_PORT,
            server_public_key: STANDARD.encode([9_u8; 32]),
        }),
        tls_like: Some(TlsLikeEndpoint {
            port: DEFAULT_TLS_LIKE_PORT,
            server_public_key: STANDARD.encode([9_u8; 32]),
            certificate_sha256: STANDARD.encode([10_u8; 32]),
            https: None,
        }),
    };
    assert!(bootstrap_matches_profile(&bootstrap, &profile));
    assert!(ensure_repair_ipv6_compatible(false, false).is_ok());
    assert!(ensure_repair_ipv6_compatible(false, true).is_ok());
    assert!(ensure_repair_ipv6_compatible(true, true).is_ok());
    assert!(ensure_repair_ipv6_compatible(true, false).is_err());
}

#[test]
fn uninstall_requires_both_the_owner_and_server_identity() {
    let server_id = ServerId::new();
    let other_server_id = ServerId::new();
    let owner_member_id = MemberId::new();
    let certificate = "-----BEGIN CERTIFICATE-----\nowner\n-----END CERTIFICATE-----\n";
    let configuration = serde_json::json!({
        "schema_version": 1,
        "owner_certificate_pem": certificate,
    })
    .to_string();
    let authorization = serde_json::json!({
        "schema_version": 1,
        "server_id": server_id,
        "members": [{
            "id": owner_member_id,
            "name": "Owner",
            "role": "owner"
        }],
        "devices": [{
            "member_id": owner_member_id,
            "wireguard_public_key": "owner-wireguard-key",
            "management_certificate_pem": certificate
        }]
    })
    .to_string();

    assert!(uninstall_identity_matches(
        &configuration,
        &authorization,
        server_id,
        certificate,
    ));
    let secure_configuration = serde_json::json!({
        "schema_version": 2,
        "owner_certificate_pem": certificate,
        "dns_upstream": {
            "mode": "dns_over_tls",
            "endpoints": [{
                "address": "1.1.1.1",
                "authentication_name": "one.one.one.one"
            }]
        }
    })
    .to_string();
    assert!(uninstall_identity_matches(
        &secure_configuration,
        &authorization,
        server_id,
        certificate,
    ));
    let https_configuration = serde_json::json!({
        "schema_version": 4,
        "owner_certificate_pem": certificate,
        "dns_upstream": {
            "mode": "dns_over_https",
            "endpoints": [{
                "address": "1.1.1.1",
                "authentication_name": "cloudflare-dns.com",
                "path": "/dns-query"
            }]
        }
    })
    .to_string();
    assert!(uninstall_identity_matches(
        &https_configuration,
        &authorization,
        server_id,
        certificate,
    ));
    assert!(!uninstall_identity_matches(
        &configuration,
        &authorization,
        other_server_id,
        certificate,
    ));
    assert!(!uninstall_identity_matches(
        &configuration,
        &authorization,
        server_id,
        "different owner",
    ));
    assert!(!uninstall_identity_matches(
        &configuration,
        "not json",
        server_id,
        certificate,
    ));
}

#[test]
fn transferred_owner_is_authoritative_for_reinstall_and_uninstall() {
    let server_id = ServerId::new();
    let previous_owner_id = MemberId::new();
    let current_owner_id = MemberId::new();
    let previous_certificate = "previous-owner-certificate";
    let current_certificate = "current-owner-certificate";
    let configuration = serde_json::json!({
        "schema_version": 1,
        "owner_certificate_pem": previous_certificate,
    })
    .to_string();
    let authorization = serde_json::json!({
        "schema_version": 1,
        "server_id": server_id,
        "members": [
            { "id": previous_owner_id, "name": "Previous", "role": "member", "administrator": true },
            { "id": current_owner_id, "name": "Current", "role": "owner" }
        ],
        "devices": [
            {
                "member_id": previous_owner_id,
                "wireguard_public_key": "previous-wireguard-key",
                "management_certificate_pem": previous_certificate
            },
            {
                "member_id": current_owner_id,
                "wireguard_public_key": "current-wireguard-key",
                "management_certificate_pem": current_certificate
            }
        ]
    })
    .to_string();

    assert!(authorization_owner_matches(
        &authorization,
        server_id,
        current_certificate,
        Some("current-wireguard-key"),
    ));
    assert!(!authorization_owner_matches(
        &authorization,
        server_id,
        previous_certificate,
        Some("previous-wireguard-key"),
    ));
    assert!(uninstall_identity_matches(
        &configuration,
        &authorization,
        server_id,
        current_certificate,
    ));
    assert!(!uninstall_identity_matches(
        &configuration,
        &authorization,
        server_id,
        previous_certificate,
    ));
}

#[test]
fn server_backup_request_is_owner_bound_and_keeps_secrets_out_of_remote_arguments() {
    let destination = std::env::temp_dir().join(format!(
        "sirinvpn-installer-test-{}.sirinvpn-server-backup",
        Uuid::new_v4()
    ));
    let server = LocalIdentity::generate("Backup server").unwrap();
    let owner = LocalIdentity::generate("Backup owner").unwrap();
    let server_id = ServerId::new();
    let profile = ServerProfile {
        favorite: false,
        schema_version: 1,
        id: server_id,
        name: "Backup target".to_owned(),
        endpoint: ServerEndpoint {
            host: "203.0.113.44".to_owned(),
            wireguard_port: 51_820,
        },
        endpoint_generation: 0,
        pending_previous_endpoint: None,
        pending_previous_transports: None,
        endpoint_discovery_port: None,
        alternate_endpoint_hosts: Vec::new(),
        client_tunnel_address: "10.77.0.2".parse().unwrap(),
        server_tunnel_address: SERVER_TUNNEL_ADDRESS.parse().unwrap(),
        server_wireguard_public_key: server.public.wireguard_public_key,
        pinned_server_certificate_pem: server.public.management_certificate_pem,
        client_management_certificate_pem: owner.public.management_certificate_pem.clone(),
        identity_reference: server_id.to_string(),
        role: ServerRole::Owner,
        administrator: false,
        member_id: None,
        device_id: None,
        ipv6_tunnel_enabled: false,
        obfuscated_udp: None,
        tcp_fallback: None,
        tls_like: None,
    };
    let mut request = ServerBackupRequest {
        profile,
        target: SshTarget {
            host: "203.0.113.44".to_owned(),
            port: 22,
            username: "root".to_owned(),
            authentication: SshAuthentication::Agent,
            sudo_password: None,
            expected_host_key_sha256: Some("SHA256:test".to_owned()),
        },
        server_binary: "/tmp/sirinvpn-server".into(),
        identity: owner.public,
        destination,
        password: Zeroizing::new("correct horse battery staple".to_owned()),
    };
    assert!(validate_server_backup_request(&request).is_ok());

    let command = server_backup_snapshot_command(
        "/tmp/staged/sirinvpn-server",
        server_id,
        "/tmp/staged/owner.crt",
    );
    assert!(command.contains("backup-state"));
    assert!(command.contains("--state-directory /etc/sirinvpn"));
    assert!(!command.contains(request.password.as_str()));
    assert!(!command.contains(request.destination.to_string_lossy().as_ref()));

    request.password = Zeroizing::new("too short".to_owned());
    assert!(matches!(
        validate_server_backup_request(&request),
        Err(InstallerError::ServerBackup(
            ServerBackupError::WeakPassword
        ))
    ));
    request.password = Zeroizing::new("correct horse battery staple".to_owned());
    request.profile.role = ServerRole::Member;
    assert!(matches!(
        validate_server_backup_request(&request),
        Err(InstallerError::InvalidInput(_))
    ));
    request.profile.role = ServerRole::Owner;
    fs::write(&request.destination, b"existing").unwrap();
    assert!(matches!(
        validate_server_backup_request(&request),
        Err(InstallerError::ServerBackup(
            ServerBackupError::DestinationExists
        ))
    ));
    fs::remove_file(&request.destination).unwrap();
}
