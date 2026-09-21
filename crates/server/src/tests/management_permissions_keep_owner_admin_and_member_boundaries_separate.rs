use super::*;

#[test]
fn management_permissions_keep_owner_admin_and_member_boundaries_separate() {
    let owner = CallerAuthorization {
        role: ServerRole::Owner,
        administrator: false,
        device_id: None,
        wireguard_public_key: None,
    };
    let admin = CallerAuthorization {
        role: ServerRole::Member,
        administrator: true,
        device_id: None,
        wireguard_public_key: None,
    };
    let member = CallerAuthorization {
        role: ServerRole::Member,
        administrator: false,
        device_id: None,
        wireguard_public_key: None,
    };

    assert!(owner.can_manage());
    assert!(can_manage_member(owner, ServerRole::Owner, false));
    assert!(can_manage_member(owner, ServerRole::Member, true));
    assert!(can_manage_member(owner, ServerRole::Member, false));

    assert!(admin.can_manage());
    assert!(can_manage_member(admin, ServerRole::Member, false));
    assert!(!can_manage_member(admin, ServerRole::Member, true));
    assert!(!can_manage_member(admin, ServerRole::Owner, false));

    assert!(!member.can_manage());
    assert!(!can_manage_member(member, ServerRole::Member, false));
}

#[test]
fn initialization_is_idempotent_for_the_same_owner() {
    let directory = tempfile::tempdir().unwrap();
    let paths = ServerPaths::under(directory.path());
    let owner = LocalIdentity::generate("Owner").unwrap();
    let server_id = ServerId::new();
    let first = initialize(
        &paths,
        "Test",
        &owner.public.management_certificate_pem,
        server_id,
        &owner.public.wireguard_public_key,
        51_820,
    )
    .unwrap();
    let second = initialize(
        &paths,
        "Test",
        &owner.public.management_certificate_pem,
        server_id,
        &owner.public.wireguard_public_key,
        51_820,
    )
    .unwrap();
    assert_eq!(first.wireguard_public_key, second.wireguard_public_key);
    assert_eq!(
        first.management_certificate_pem,
        second.management_certificate_pem
    );
}

#[test]
fn server_backup_snapshot_is_bounded_validated_and_owner_bound() {
    let directory = tempfile::tempdir().unwrap();
    let paths = ServerPaths::under(directory.path());
    let owner = LocalIdentity::generate("Backup owner").unwrap();
    let other = LocalIdentity::generate("Other owner").unwrap();
    let server_id = ServerId::new();
    initialize_with_transport_capabilities(
        &paths,
        "Backup target",
        &owner.public.management_certificate_pem,
        server_id,
        &owner.public.wireguard_public_key,
        51_820,
        ServerCapabilities {
            obfuscated_udp_port: Some(443),
            tcp_fallback_port: Some(443),
            ..ServerCapabilities::default()
        },
    )
    .unwrap();

    let snapshot =
        export_backup_state(&paths, server_id, &owner.public.management_certificate_pem).unwrap();
    let decoded: ServerBackupState = serde_json::from_slice(snapshot.as_slice()).unwrap();
    assert_eq!(decoded.schema_version, SERVER_BACKUP_STATE_SCHEMA_VERSION);
    assert_eq!(decoded.server_id, server_id);
    assert!(decoded.configuration_json.contains("Backup target"));
    assert!(!decoded.wireguard_private_key.is_empty());
    assert!(!decoded.management_certificate_pem.is_empty());
    assert!(!decoded.management_private_key_pem.is_empty());
    assert!(decoded.authorization_required);
    assert!(decoded.authorization_json.is_some());
    assert!(decoded.transport_private_key.is_some());

    assert!(
        export_backup_state(&paths, server_id, &other.public.management_certificate_pem).is_err()
    );

    fs::set_permissions(
        &paths.wireguard_private_key,
        fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    assert!(
        export_backup_state(&paths, server_id, &owner.public.management_certificate_pem).is_err()
    );
}

#[test]
fn server_backup_restore_preserves_private_identity_and_refuses_occupied_state() {
    let source_directory = tempfile::tempdir().unwrap();
    let source = ServerPaths::under(source_directory.path());
    let owner = LocalIdentity::generate("Restore owner").unwrap();
    let other = LocalIdentity::generate("Other owner").unwrap();
    let server_id = ServerId::new();
    initialize_with_transport_capabilities(
        &source,
        "Restore target",
        &owner.public.management_certificate_pem,
        server_id,
        &owner.public.wireguard_public_key,
        51_820,
        ServerCapabilities {
            obfuscated_udp_port: Some(443),
            tcp_fallback_port: Some(443),
            ..ServerCapabilities::default()
        },
    )
    .unwrap();
    let snapshot =
        export_backup_state(&source, server_id, &owner.public.management_certificate_pem).unwrap();

    let envelope_directory = tempfile::tempdir().unwrap();
    let envelope = envelope_directory
        .path()
        .join("restore.sirinvpn-server-backup");
    write_encrypted_server_backup(
        &envelope,
        snapshot.as_slice(),
        "correct horse battery staple",
    )
    .unwrap();
    let decrypted =
        read_encrypted_server_backup(&envelope, "correct horse battery staple").unwrap();
    assert_eq!(decrypted.metadata().server_id, server_id);
    assert_eq!(decrypted.snapshot(), snapshot.as_slice());

    let target_directory = tempfile::tempdir().unwrap();
    let target = ServerPaths::under(target_directory.path());
    restore_backup_state(
        &target,
        server_id,
        &owner.public.management_certificate_pem,
        decrypted.snapshot(),
    )
    .unwrap();
    validate_state(&target).unwrap();
    for (source_path, target_path) in [
        (&source.configuration, &target.configuration),
        (&source.wireguard_private_key, &target.wireguard_private_key),
        (&source.transport_private_key, &target.transport_private_key),
        (&source.tls_certificate, &target.tls_certificate),
        (&source.tls_private_key, &target.tls_private_key),
        (&source.authorization, &target.authorization),
    ] {
        assert_eq!(
            fs::read(source_path).unwrap(),
            fs::read(target_path).unwrap()
        );
        assert_eq!(
            fs::metadata(target_path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    let mismatch_directory = tempfile::tempdir().unwrap();
    let mismatch = ServerPaths::under(mismatch_directory.path());
    assert!(
        restore_backup_state(
            &mismatch,
            server_id,
            &other.public.management_certificate_pem,
            snapshot.as_slice(),
        )
        .is_err()
    );
    assert!(!mismatch.configuration.exists());

    let occupied_directory = tempfile::tempdir().unwrap();
    let occupied = ServerPaths::under(occupied_directory.path());
    fs::write(&occupied.configuration, b"do-not-replace").unwrap();
    assert!(
        restore_backup_state(
            &occupied,
            server_id,
            &owner.public.management_certificate_pem,
            snapshot.as_slice(),
        )
        .is_err()
    );
    assert_eq!(
        fs::read(&occupied.configuration).unwrap(),
        b"do-not-replace"
    );
}

#[test]
fn ipv6_capability_migration_preserves_identity_and_is_not_implicitly_reversed() {
    let directory = tempfile::tempdir().unwrap();
    let paths = ServerPaths::under(directory.path());
    let owner = LocalIdentity::generate("Owner").unwrap();
    let server_id = ServerId::new();
    let original = initialize(
        &paths,
        "Migration target",
        &owner.public.management_certificate_pem,
        server_id,
        &owner.public.wireguard_public_key,
        51_820,
    )
    .unwrap();
    assert!(!original.ipv6_tunnel_enabled);
    let legacy_shape: serde_json::Value =
        serde_json::from_slice(&fs::read(&paths.configuration).unwrap()).unwrap();
    assert!(legacy_shape.get("ipv6_tunnel_enabled").is_none());
    let wireguard_key = fs::read(&paths.wireguard_private_key).unwrap();
    let tls_key = fs::read(&paths.tls_private_key).unwrap();
    let authorization = fs::read(&paths.authorization).unwrap();

    let migrated = initialize_with_capabilities(
        &paths,
        "Migration target",
        &owner.public.management_certificate_pem,
        server_id,
        &owner.public.wireguard_public_key,
        51_820,
        Some(true),
    )
    .unwrap();
    assert!(migrated.ipv6_tunnel_enabled);
    let migrated_shape: serde_json::Value =
        serde_json::from_slice(&fs::read(&paths.configuration).unwrap()).unwrap();
    assert_eq!(migrated_shape["ipv6_tunnel_enabled"], true);
    assert_eq!(migrated.wireguard_public_key, original.wireguard_public_key);
    assert_eq!(
        migrated.management_certificate_pem,
        original.management_certificate_pem
    );
    assert_eq!(
        fs::read(&paths.wireguard_private_key).unwrap(),
        wireguard_key
    );
    assert_eq!(fs::read(&paths.tls_private_key).unwrap(), tls_key);
    assert_eq!(fs::read(&paths.authorization).unwrap(), authorization);
    validate_state(&paths).unwrap();

    let retried = initialize(
        &paths,
        "Migration target",
        &owner.public.management_certificate_pem,
        server_id,
        &owner.public.wireguard_public_key,
        51_820,
    )
    .unwrap();
    assert!(retried.ipv6_tunnel_enabled);
    assert!(load_configuration(&paths).unwrap().ipv6_tunnel_enabled);
}

#[test]
fn transport_capability_migration_preserves_and_validates_every_existing_identity() {
    let directory = tempfile::tempdir().unwrap();
    let paths = ServerPaths::under(directory.path());
    let owner = LocalIdentity::generate("Owner").unwrap();
    let server_id = ServerId::new();
    let original = initialize(
        &paths,
        "Transport migration target",
        &owner.public.management_certificate_pem,
        server_id,
        &owner.public.wireguard_public_key,
        51_820,
    )
    .unwrap();
    assert_eq!(original.obfuscated_udp, None);
    assert_eq!(original.tcp_fallback, None);
    assert!(!paths.transport_private_key.exists());
    let wireguard_key = fs::read(&paths.wireguard_private_key).unwrap();
    let tls_key = fs::read(&paths.tls_private_key).unwrap();
    let authorization = fs::read(&paths.authorization).unwrap();

    let migrated = initialize_with_transport_capabilities(
        &paths,
        "Transport migration target",
        &owner.public.management_certificate_pem,
        server_id,
        &owner.public.wireguard_public_key,
        51_820,
        ServerCapabilities {
            public_host: None,
            previous_public_host: None,
            alternate_endpoint_hosts: None,
            ipv6_tunnel_enabled: None,
            obfuscated_udp_port: Some(443),
            tcp_fallback_port: None,
            https: None,
            https_certificate: None,
            update_transport_ports: false,
            disable_https: false,
            tls_like_port: None,
            dns_upstream: None,
            private_dns_records: None,
        },
    )
    .unwrap();
    let endpoint = migrated.obfuscated_udp.clone().unwrap();
    assert_eq!(endpoint.port, 443);
    assert_eq!(migrated.wireguard_public_key, original.wireguard_public_key);
    assert_eq!(
        migrated.management_certificate_pem,
        original.management_certificate_pem
    );
    assert_eq!(
        fs::read(&paths.wireguard_private_key).unwrap(),
        wireguard_key
    );
    assert_eq!(fs::read(&paths.tls_private_key).unwrap(), tls_key);
    assert_eq!(fs::read(&paths.authorization).unwrap(), authorization);
    let transport_key = fs::read(&paths.transport_private_key).unwrap();
    validate_state(&paths).unwrap();

    let retried = initialize_with_transport_capabilities(
        &paths,
        "Transport migration target",
        &owner.public.management_certificate_pem,
        server_id,
        &owner.public.wireguard_public_key,
        51_820,
        ServerCapabilities {
            public_host: None,
            previous_public_host: None,
            alternate_endpoint_hosts: None,
            ipv6_tunnel_enabled: None,
            obfuscated_udp_port: Some(444),
            tcp_fallback_port: None,
            https: None,
            https_certificate: None,
            update_transport_ports: false,
            disable_https: false,
            tls_like_port: None,
            dns_upstream: None,
            private_dns_records: None,
        },
    )
    .unwrap();
    assert_eq!(retried.obfuscated_udp, Some(endpoint));
    assert_eq!(
        fs::read(&paths.transport_private_key).unwrap(),
        transport_key
    );

    let tcp_migrated = initialize_with_transport_capabilities(
        &paths,
        "Transport migration target",
        &owner.public.management_certificate_pem,
        server_id,
        &owner.public.wireguard_public_key,
        51_820,
        ServerCapabilities {
            public_host: None,
            previous_public_host: None,
            alternate_endpoint_hosts: None,
            ipv6_tunnel_enabled: None,
            obfuscated_udp_port: Some(444),
            tcp_fallback_port: Some(443),
            https: None,
            https_certificate: None,
            update_transport_ports: false,
            disable_https: false,
            tls_like_port: Some(443),
            dns_upstream: None,
            private_dns_records: None,
        },
    )
    .unwrap();
    let tcp_endpoint = tcp_migrated.tcp_fallback.clone().unwrap();
    let tls_endpoint = tcp_migrated.tls_like.clone().unwrap();
    assert_eq!(tcp_endpoint.port, 443);
    assert_eq!(
        tcp_endpoint.server_public_key,
        retried.obfuscated_udp.as_ref().unwrap().server_public_key
    );
    assert_eq!(tls_endpoint.port, tcp_endpoint.port);
    assert_eq!(
        tls_endpoint.server_public_key,
        tcp_endpoint.server_public_key
    );
    assert_eq!(
        STANDARD
            .decode(&tls_endpoint.certificate_sha256)
            .unwrap()
            .len(),
        32
    );
    assert_eq!(ensure_tls_like_identity(&paths, 443).unwrap(), tls_endpoint);
    assert_eq!(
        fs::read(&paths.wireguard_private_key).unwrap(),
        wireguard_key
    );
    assert_eq!(fs::read(&paths.tls_private_key).unwrap(), tls_key);
    assert_eq!(fs::read(&paths.authorization).unwrap(), authorization);
    assert_eq!(
        fs::read(&paths.transport_private_key).unwrap(),
        transport_key
    );
    validate_state(&paths).unwrap();

    fs::write(&paths.transport_private_key, STANDARD.encode([17_u8; 32])).unwrap();
    assert!(validate_state(&paths).is_err());
}

#[test]
fn tls_like_migration_refuses_to_replace_an_existing_tcp_port() {
    let directory = tempfile::tempdir().unwrap();
    let paths = ServerPaths::under(directory.path());
    let owner = LocalIdentity::generate("Owner").unwrap();
    let server_id = ServerId::new();
    initialize_with_transport_capabilities(
        &paths,
        "Custom TCP target",
        &owner.public.management_certificate_pem,
        server_id,
        &owner.public.wireguard_public_key,
        51_820,
        ServerCapabilities {
            tcp_fallback_port: Some(8443),
            ..ServerCapabilities::default()
        },
    )
    .unwrap();
    let configuration_bytes = fs::read(&paths.configuration).unwrap();
    let transport_key = fs::read(&paths.transport_private_key).unwrap();

    let error = initialize_with_transport_capabilities(
        &paths,
        "Custom TCP target",
        &owner.public.management_certificate_pem,
        server_id,
        &owner.public.wireguard_public_key,
        51_820,
        ServerCapabilities {
            tcp_fallback_port: Some(443),
            https: None,
            https_certificate: None,
            update_transport_ports: false,
            disable_https: false,
            tls_like_port: Some(443),
            ..ServerCapabilities::default()
        },
    )
    .unwrap_err();

    assert!(error.to_string().contains("different public port"));
    assert_eq!(fs::read(&paths.configuration).unwrap(), configuration_bytes);
    assert_eq!(
        fs::read(&paths.transport_private_key).unwrap(),
        transport_key
    );
    validate_state(&paths).unwrap();
}
