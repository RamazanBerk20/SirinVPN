use super::*;

#[test]
fn https_names_ports_and_imported_certificates_survive_backup_without_rotating_server_identity() {
    let directory = tempfile::tempdir().unwrap();
    let paths = ServerPaths::under(directory.path().join("state"));
    let owner = LocalIdentity::generate("Owner").unwrap();
    let server_id = ServerId::new();
    let initial = initialize(
        &paths,
        "HTTPS VPS",
        &owner.public.management_certificate_pem,
        server_id,
        &owner.public.wireguard_public_key,
        51_820,
    )
    .unwrap();
    let original_key = fs::read(&paths.wireguard_private_key).unwrap();
    let management_key = fs::read(&paths.tls_private_key).unwrap();
    let https = sirinvpn_protocol::HttpsTransport {
        server_name: "vpn.example.org".into(),
        path: "/connect".into(),
    };
    let mut capabilities = ServerCapabilities {
        obfuscated_udp_port: Some(9443),
        tcp_fallback_port: Some(4443),
        tls_like_port: Some(4443),
        https: Some(https.clone()),
        update_transport_ports: true,
        ..Default::default()
    };
    let generated = initialize_with_transport_capabilities(
        &paths,
        "HTTPS VPS",
        &owner.public.management_certificate_pem,
        server_id,
        &owner.public.wireguard_public_key,
        51_825,
        capabilities.clone(),
    )
    .unwrap();
    assert_eq!(generated.wireguard_public_key, initial.wireguard_public_key);
    assert_eq!(generated.wireguard_port, 51_825);
    assert_eq!(
        generated.tls_like.as_ref().unwrap().https,
        Some(https.clone())
    );
    let mut configuration = load_configuration(&paths).unwrap();
    assert_eq!(configuration.schema_version, 7);
    validate_state(&paths).unwrap();
    configuration.schema_version = 1;
    assert!(validate_configuration(&configuration).is_err());

    let certificate_key = KeyPair::generate_for(&PKCS_ED25519).unwrap();
    let certificate = CertificateParams::new(vec![https.server_name.clone()])
        .unwrap()
        .self_signed(&certificate_key)
        .unwrap();
    let certificate_path = directory.path().join("public-chain.pem");
    let key_path = directory.path().join("private-key.pem");
    fs::write(&certificate_path, certificate.pem()).unwrap();
    fs::write(&key_path, certificate_key.serialize_pem()).unwrap();
    capabilities.https_certificate = Some(HttpsCertificatePaths {
        certificate: certificate_path.clone(),
        private_key: key_path,
    });
    let imported = initialize_with_transport_capabilities(
        &paths,
        "HTTPS VPS",
        &owner.public.management_certificate_pem,
        server_id,
        &owner.public.wireguard_public_key,
        51_825,
        capabilities.clone(),
    )
    .unwrap();
    assert_eq!(
        imported.tls_like.as_ref().unwrap().certificate_sha256,
        STANDARD.encode(Sha256::digest(certificate.der().as_ref()))
    );
    assert_ne!(
        imported.tls_like.as_ref().unwrap().certificate_sha256,
        generated.tls_like.as_ref().unwrap().certificate_sha256
    );
    assert_eq!(
        imported.tls_like.as_ref().unwrap().server_public_key,
        generated.tls_like.as_ref().unwrap().server_public_key
    );
    assert_eq!(
        fs::read(&paths.wireguard_private_key).unwrap(),
        original_key
    );
    assert_eq!(fs::read(&paths.tls_private_key).unwrap(), management_key);
    validate_state(&paths).unwrap();

    let snapshot =
        export_backup_state(&paths, server_id, &owner.public.management_certificate_pem).unwrap();
    let decoded: serde_json::Value = serde_json::from_slice(&snapshot).unwrap();
    assert_eq!(decoded["schema_version"], 2);
    let envelope = directory.path().join("vps.sirbak");
    write_encrypted_server_backup(&envelope, &snapshot, "correct horse battery staple").unwrap();
    let backup = read_encrypted_server_backup(&envelope, "correct horse battery staple").unwrap();
    assert_eq!(backup.metadata().tls_like, imported.tls_like);
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

    // Changing the name to one absent from the certificate must fail before any key/config mutation.
    let before = fs::read(&paths.configuration).unwrap();
    let before_key = fs::read(&paths.https_private_key).unwrap();
    capabilities.https.as_mut().unwrap().server_name = "wrong.example.org".into();
    assert!(
        initialize_with_transport_capabilities(
            &paths,
            "HTTPS VPS",
            &owner.public.management_certificate_pem,
            server_id,
            &owner.public.wireguard_public_key,
            51_825,
            capabilities.clone()
        )
        .is_err()
    );
    assert_eq!(fs::read(&paths.configuration).unwrap(), before);
    assert_eq!(fs::read(&paths.https_private_key).unwrap(), before_key);
    capabilities.https = None;
    capabilities.https_certificate = None;
    capabilities.disable_https = true;
    let legacy = initialize_with_transport_capabilities(
        &paths,
        "HTTPS VPS",
        &owner.public.management_certificate_pem,
        server_id,
        &owner.public.wireguard_public_key,
        51_825,
        capabilities,
    )
    .unwrap();
    assert!(legacy.tls_like.as_ref().unwrap().https.is_none());
    assert!(!paths.https_private_key.exists());
    validate_state(&paths).unwrap();
}
