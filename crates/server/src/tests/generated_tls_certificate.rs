use super::*;

fn certificate_pin(configuration: &ServerConfiguration) -> String {
    configuration
        .tls_like
        .as_ref()
        .unwrap()
        .certificate_sha256
        .clone()
}

#[test]
fn new_servers_get_a_generated_certificate_that_survives_repair_https_changes_and_backup() {
    let directory = tempfile::tempdir().unwrap();
    let paths = ServerPaths::under(directory.path().join("state"));
    let owner = LocalIdentity::generate("Owner").unwrap();
    let server_id = ServerId::new();
    let mut capabilities = ServerCapabilities {
        tcp_fallback_port: Some(443),
        tls_like_port: Some(443),
        public_host: Some("8.8.8.8".into()),
        ..Default::default()
    };
    let initialize = |capabilities: &ServerCapabilities| {
        initialize_with_transport_capabilities(
            &paths,
            "Generated certificate VPS",
            &owner.public.management_certificate_pem,
            server_id,
            &owner.public.wireguard_public_key,
            51_820,
            capabilities.clone(),
        )
        .unwrap()
    };
    initialize(&capabilities);
    let configuration = load_configuration(&paths).unwrap();
    assert_eq!(configuration.schema_version, 9);
    validate_state(&paths).unwrap();
    let pem = configuration.https_certificate_pem.clone().unwrap();
    let der = CertificateDer::from_pem_slice(pem.as_bytes()).unwrap();
    assert_eq!(
        certificate_pin(&configuration),
        STANDARD.encode(Sha256::digest(der.as_ref()))
    );
    let (_, certificate) = x509_parser::parse_x509_certificate(der.as_ref()).unwrap();
    assert_eq!(
        certificate.public_key().algorithm.algorithm.to_id_string(),
        "1.2.840.10045.2.1"
    );
    assert_eq!(
        certificate
            .subject()
            .iter_common_name()
            .next()
            .unwrap()
            .as_str()
            .unwrap(),
        "localhost"
    );
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let validity = certificate.validity();
    assert!((now - validity.not_before.timestamp()).abs() < 600);
    assert_eq!(
        validity.not_after.timestamp() - validity.not_before.timestamp(),
        3_650 * 86_400
    );
    assert!(!der.windows(11).any(|window| window == b"example.com"));
    let transport_key = fs::read(&paths.transport_private_key).unwrap();
    transport_tls_configuration(&paths, &configuration, &transport_key).unwrap();

    // Repair keeps the pin every device already holds.
    initialize(&capabilities);
    let repaired = load_configuration(&paths).unwrap();
    assert_eq!(certificate_pin(&repaired), certificate_pin(&configuration));
    assert_eq!(
        repaired.https_certificate_pem,
        configuration.https_certificate_pem
    );

    // HTTPS without an imported certificate uses its named certificate and drops the generated key.
    capabilities.https = Some(sirinvpn_protocol::HttpsTransport {
        server_name: "vpn.example.org".into(),
        path: "/connect".into(),
        cdn: false,
    });
    initialize(&capabilities);
    let https = load_configuration(&paths).unwrap();
    assert_eq!(https.schema_version, 8);
    assert!(https.https_certificate_pem.is_none());
    assert!(!paths.https_private_key.exists());
    validate_state(&paths).unwrap();

    // Leaving HTTPS generates a fresh certificate rather than the old fixed one.
    capabilities.https = None;
    capabilities.disable_https = true;
    initialize(&capabilities);
    let disabled = load_configuration(&paths).unwrap();
    assert_eq!(disabled.schema_version, 9);
    assert_ne!(certificate_pin(&disabled), certificate_pin(&configuration));
    assert_ne!(certificate_pin(&disabled), certificate_pin(&https));
    validate_state(&paths).unwrap();

    let snapshot =
        export_backup_state(&paths, server_id, &owner.public.management_certificate_pem).unwrap();
    let envelope = directory.path().join("vps.sirbak");
    write_encrypted_server_backup(&envelope, &snapshot, "correct horse battery staple").unwrap();
    let backup = read_encrypted_server_backup(&envelope, "correct horse battery staple").unwrap();
    assert_eq!(backup.metadata().tls_like, disabled.tls_like);
    let restored = ServerPaths::under(directory.path().join("restored"));
    fs::create_dir(&restored.state_directory).unwrap();
    restore_backup_state(
        &restored,
        server_id,
        &owner.public.management_certificate_pem,
        backup.snapshot(),
    )
    .unwrap();
    validate_state(&restored).unwrap();
    assert_eq!(
        fs::read(&restored.https_private_key).unwrap(),
        fs::read(&paths.https_private_key).unwrap()
    );
}

#[test]
fn schema_nine_requires_a_generated_certificate_without_https() {
    let directory = tempfile::tempdir().unwrap();
    let paths = ServerPaths::under(directory.path().join("state"));
    let owner = LocalIdentity::generate("Owner").unwrap();
    initialize_with_transport_capabilities(
        &paths,
        "Generated certificate VPS",
        &owner.public.management_certificate_pem,
        ServerId::new(),
        &owner.public.wireguard_public_key,
        51_820,
        ServerCapabilities {
            tcp_fallback_port: Some(443),
            tls_like_port: Some(443),
            public_host: Some("8.8.8.8".into()),
            ..Default::default()
        },
    )
    .unwrap();
    let configuration = load_configuration(&paths).unwrap();
    validate_configuration(&configuration).unwrap();
    let mut older = configuration.clone();
    older.schema_version = 8;
    assert!(validate_configuration(&older).is_err());
    let mut missing = configuration;
    missing.https_certificate_pem = None;
    assert!(validate_configuration(&missing).is_err());
}
