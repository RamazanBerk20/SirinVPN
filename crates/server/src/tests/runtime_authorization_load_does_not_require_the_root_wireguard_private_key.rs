use super::*;

#[test]
fn runtime_authorization_load_does_not_require_the_root_wireguard_private_key() {
    let directory = tempfile::tempdir().unwrap();
    let paths = ServerPaths::under(directory.path());
    let owner = LocalIdentity::generate("Runtime boundary owner").unwrap();
    initialize(
        &paths,
        "Runtime boundary target",
        &owner.public.management_certificate_pem,
        ServerId::new(),
        &owner.public.wireguard_public_key,
        51_820,
    )
    .unwrap();

    fs::set_permissions(
        &paths.wireguard_private_key,
        fs::Permissions::from_mode(0o000),
    )
    .unwrap();
    assert!(load_runtime_authorization(&paths).unwrap().is_some());
    assert!(validate_state(&paths).is_err());
}

#[test]
fn initialization_does_not_replace_an_invalid_existing_identity() {
    let directory = tempfile::tempdir().unwrap();
    let paths = ServerPaths::under(directory.path());
    let owner = LocalIdentity::generate("Owner").unwrap();
    let server_id = ServerId::new();
    initialize(
        &paths,
        "Original server",
        &owner.public.management_certificate_pem,
        server_id,
        &owner.public.wireguard_public_key,
        51_820,
    )
    .unwrap();
    let wireguard_key = fs::read(&paths.wireguard_private_key).unwrap();
    let tls_key = fs::read(&paths.tls_private_key).unwrap();
    let mut configuration: serde_json::Value =
        serde_json::from_slice(&fs::read(&paths.configuration).unwrap()).unwrap();
    configuration["management_port"] = serde_json::json!(9443);
    fs::write(
        &paths.configuration,
        serde_json::to_vec(&configuration).unwrap(),
    )
    .unwrap();

    assert!(
        initialize(
            &paths,
            "Original server",
            &owner.public.management_certificate_pem,
            server_id,
            &owner.public.wireguard_public_key,
            51_820,
        )
        .is_err()
    );
    assert_eq!(
        fs::read(&paths.wireguard_private_key).unwrap(),
        wireguard_key
    );
    assert_eq!(fs::read(&paths.tls_private_key).unwrap(), tls_key);
}

#[test]
fn legacy_owner_state_expands_without_rewriting_schema_one_configuration() {
    let directory = tempfile::tempdir().unwrap();
    let paths = ServerPaths::under(directory.path());
    let owner = LocalIdentity::generate("Owner").unwrap();
    let server_id = ServerId::new();
    initialize(
        &paths,
        "Test",
        &owner.public.management_certificate_pem,
        server_id,
        &owner.public.wireguard_public_key,
        51_820,
    )
    .unwrap();
    let configuration_before = fs::read(&paths.configuration).unwrap();
    let tls_key_before = fs::read(&paths.tls_private_key).unwrap();
    fs::remove_dir_all(paths.authorization.parent().unwrap()).unwrap();
    fs::remove_file(&paths.authorization_required).unwrap();
    validate_state(&paths).unwrap();

    initialize(
        &paths,
        "Test",
        &owner.public.management_certificate_pem,
        server_id,
        &owner.public.wireguard_public_key,
        51_820,
    )
    .unwrap();

    assert_eq!(
        fs::read(&paths.configuration).unwrap(),
        configuration_before
    );
    assert_eq!(fs::read(&paths.tls_private_key).unwrap(), tls_key_before);
    assert!(paths.authorization_required.is_file());
    let authorization = load_authorization(&paths.authorization).unwrap();
    assert_eq!(authorization.server_id, server_id);
    assert_eq!(authorization.devices.len(), 1);
    assert_eq!(
        authorization.devices[0].wireguard_public_key,
        owner.public.wireguard_public_key
    );
}

#[test]
fn a_claimed_server_rejects_a_different_owner() {
    let directory = tempfile::tempdir().unwrap();
    let paths = ServerPaths::under(directory.path());
    let first = LocalIdentity::generate("First owner").unwrap();
    initialize(
        &paths,
        "Test",
        &first.public.management_certificate_pem,
        ServerId::new(),
        &first.public.wireguard_public_key,
        51_820,
    )
    .unwrap();
    let second = LocalIdentity::generate("Second owner").unwrap();
    assert!(
        initialize(
            &paths,
            "Test",
            &second.public.management_certificate_pem,
            ServerId::new(),
            &second.public.wireguard_public_key,
            51_820,
        )
        .is_err()
    );
}

#[test]
fn initialization_accepts_only_the_current_transferred_owner() {
    let directory = tempfile::tempdir().unwrap();
    let paths = ServerPaths::under(directory.path());
    let original = LocalIdentity::generate("Original owner").unwrap();
    let destination = LocalIdentity::generate("Destination owner").unwrap();
    let server_id = ServerId::new();
    initialize(
        &paths,
        "Test",
        &original.public.management_certificate_pem,
        server_id,
        &original.public.wireguard_public_key,
        51_820,
    )
    .unwrap();

    let mut authorization = load_authorization(&paths.authorization).unwrap();
    let destination_member_id = MemberId::new();
    let destination_device_id = DeviceId::new();
    authorization.members.push(MemberRecord {
        policy: Default::default(),
        id: destination_member_id,
        name: "Destination".to_owned(),
        role: ServerRole::Member,
        administrator: false,
        suspended: false,
    });
    authorization.devices.push(DeviceRecord {
        id: destination_device_id,
        member_id: destination_member_id,
        name: "Destination device".to_owned(),
        client_tunnel_address: authorization.allocate_member_address().unwrap(),
        wireguard_public_key: destination.public.wireguard_public_key.clone(),
        management_certificate_pem: destination.public.management_certificate_pem.clone(),
        certificate_fingerprint: certificate_fingerprint(
            &destination.public.management_certificate_pem,
        )
        .unwrap(),
        peer_communication_enabled: false,
    });
    authorization
        .transfer_ownership(destination_device_id)
        .unwrap();
    write_authorization(&paths.authorization, &authorization).unwrap();

    initialize(
        &paths,
        "Test",
        &destination.public.management_certificate_pem,
        server_id,
        &destination.public.wireguard_public_key,
        51_820,
    )
    .unwrap();
    assert!(
        initialize(
            &paths,
            "Test",
            &original.public.management_certificate_pem,
            server_id,
            &original.public.wireguard_public_key,
            51_820,
        )
        .is_err()
    );
}

#[test]
fn interface_counters_are_read_without_network_capabilities() {
    let counters =
        "Inter-| Receive | Transmit\n  sirinvpn0: 123 1 2 3 4 5 6 7 456 8 9 10 11 12 13 14\n";
    assert_eq!(
        parse_interface_counters(counters, "sirinvpn0"),
        Some((123, 456))
    );
    assert_eq!(parse_interface_counters(counters, "missing"), None);
}

#[test]
fn proc_cpu_and_memory_counters_are_parsed_without_commands() {
    let cpu = "cpu  100 20 30 400 50 6 7 8 0 0\ncpu0 1 2 3 4 5 6 7 8\n";
    assert_eq!(
        parse_cpu_counters(cpu),
        Some(CpuCounters {
            total: 621,
            idle: 450,
        })
    );
    let memory = "MemTotal:       2048 kB\nMemFree:         256 kB\nMemAvailable:    512 kB\n";
    assert_eq!(
        parse_memory_counters(memory),
        Some(MemoryCounters {
            total_bytes: 2_097_152,
            available_bytes: 524_288,
        })
    );
    assert_eq!(parse_cpu_counters("cpu invalid"), None);
    assert_eq!(parse_memory_counters("MemTotal: 2048 bytes"), None);
}

#[test]
fn live_metrics_use_only_the_previous_bounded_sample() {
    let started = Instant::now();
    let mut sampler = LiveMetricSampler::default();
    let first = sampler.sample(SystemMetricSnapshot {
        recorded_at: started,
        cpu: Some(CpuCounters {
            total: 1_000,
            idle: 600,
        }),
        memory: Some(MemoryCounters {
            total_bytes: 8_000,
            available_bytes: 3_000,
        }),
        network: Some((10_000, 20_000)),
    });
    assert_eq!(first.cpu_usage_basis_points, None);
    assert_eq!(first.memory_used_bytes, Some(5_000));
    assert_eq!(first.memory_total_bytes, Some(8_000));
    assert_eq!(first.rx_bytes_per_second, None);
    assert_eq!(first.tx_bytes_per_second, None);

    let second = sampler.sample(SystemMetricSnapshot {
        recorded_at: started + Duration::from_secs(2),
        cpu: Some(CpuCounters {
            total: 1_200,
            idle: 650,
        }),
        memory: Some(MemoryCounters {
            total_bytes: 8_000,
            available_bytes: 2_000,
        }),
        network: Some((14_000, 21_000)),
    });
    assert_eq!(second.cpu_usage_basis_points, Some(7_500));
    assert_eq!(second.memory_used_bytes, Some(6_000));
    assert_eq!(second.memory_total_bytes, Some(8_000));
    assert_eq!(second.rx_bytes_per_second, Some(2_000));
    assert_eq!(second.tx_bytes_per_second, Some(500));

    let reset = sampler.sample(SystemMetricSnapshot {
        recorded_at: started + Duration::from_secs(4),
        cpu: Some(CpuCounters {
            total: 100,
            idle: 50,
        }),
        memory: None,
        network: Some((100, 200)),
    });
    assert_eq!(reset.cpu_usage_basis_points, None);
    assert_eq!(reset.memory_used_bytes, None);
    assert_eq!(reset.rx_bytes_per_second, None);
    assert_eq!(reset.tx_bytes_per_second, None);
}

#[test]
fn management_identity_completes_a_pinned_tls_13_handshake() {
    let directory = tempfile::tempdir().unwrap();
    let paths = ServerPaths::under(directory.path());
    let owner = LocalIdentity::generate("Test owner").unwrap();
    let owner_certificate = owner.public.management_certificate_pem.clone();
    initialize(
        &paths,
        "Test",
        &owner_certificate,
        ServerId::new(),
        &owner.public.wireguard_public_key,
        51_820,
    )
    .unwrap();

    let server_tls = tls_configuration(&paths, std::slice::from_ref(&owner_certificate)).unwrap();

    let server_certificate = fs::read(&paths.tls_certificate).unwrap();
    let server_certificates: Vec<CertificateDer<'static>> =
        CertificateDer::pem_slice_iter(&server_certificate)
            .collect::<Result<_, _>>()
            .unwrap();
    let mut server_roots = RootCertStore::empty();
    for certificate in server_certificates {
        server_roots.add(certificate).unwrap();
    }

    let owner_certificates: Vec<CertificateDer<'static>> =
        CertificateDer::pem_slice_iter(owner_certificate.as_bytes())
            .collect::<Result<_, _>>()
            .unwrap();
    let owner_private_key =
        PrivateKeyDer::from_pem_slice(owner.secret.management_private_key_pem.as_bytes()).unwrap();
    let client_tls = ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_root_certificates(server_roots)
    .with_client_auth_cert(owner_certificates, owner_private_key)
    .unwrap();

    let server_name = ServerName::IpAddress(Ipv4Addr::new(10, 77, 0, 1).into());
    let mut client = ClientConnection::new(Arc::new(client_tls), server_name).unwrap();
    let mut server = ServerConnection::new(Arc::new(server_tls)).unwrap();

    for _ in 0..16 {
        if client.wants_write() {
            let mut bytes = Vec::new();
            client.write_tls(&mut bytes).unwrap();
            server.read_tls(&mut Cursor::new(bytes)).unwrap();
            server.process_new_packets().unwrap();
        }
        if server.wants_write() {
            let mut bytes = Vec::new();
            server.write_tls(&mut bytes).unwrap();
            client.read_tls(&mut Cursor::new(bytes)).unwrap();
            client.process_new_packets().unwrap();
        }
        if !client.is_handshaking() && !server.is_handshaking() {
            break;
        }
    }

    assert!(!client.is_handshaking());
    assert!(!server.is_handshaking());
    assert_eq!(
        client.protocol_version(),
        Some(rustls::ProtocolVersion::TLSv1_3)
    );
}
