use super::*;

#[test]
fn server_restore_is_profile_bound_stdin_only_and_guarded_before_identity_replacement() {
    let server = LocalIdentity::generate("Restore server").unwrap();
    let owner = LocalIdentity::generate("Restore owner").unwrap();
    let server_id = ServerId::new();
    let profile = ServerProfile {
        favorite: false,
        schema_version: 1,
        id: server_id,
        name: "Restore target".to_owned(),
        endpoint: ServerEndpoint {
            host: "203.0.113.44".to_owned(),
            wireguard_port: 51_820,
        },
        endpoint_generation: 0,
        pending_previous_endpoint: None,
        pending_previous_transports: None,
        endpoint_discovery_port: None,
        alternate_endpoint_hosts: Vec::new(),
        client_tunnel_address: "10.77.0.9".parse().unwrap(),
        server_tunnel_address: SERVER_TUNNEL_ADDRESS.parse().unwrap(),
        server_wireguard_public_key: server.public.wireguard_public_key.clone(),
        pinned_server_certificate_pem: server.public.management_certificate_pem.clone(),
        client_management_certificate_pem: owner.public.management_certificate_pem.clone(),
        identity_reference: server_id.to_string(),
        role: ServerRole::Owner,
        administrator: false,
        member_id: Some(MemberId::new()),
        device_id: Some(sirinvpn_protocol::DeviceId::new()),
        ipv6_tunnel_enabled: false,
        obfuscated_udp: None,
        tcp_fallback: None,
        tls_like: None,
    };
    let mut restore = ServerRestoreRequest {
        profile: profile.clone(),
        target: SshTarget {
            host: "203.0.113.99".to_owned(),
            port: 22,
            username: "root".to_owned(),
            authentication: SshAuthentication::Agent,
            sudo_password: None,
            expected_host_key_sha256: Some("SHA256:restore".to_owned()),
        },
        server_binary: "/tmp/sirinvpn-server".into(),
        identity: owner.public.clone(),
        source: "/tmp/restore.sirinvpn-server-backup".into(),
        password: Zeroizing::new("correct horse battery staple".to_owned()),
        replace_existing_installation: true,
    };
    assert!(validate_server_restore_request(&restore).is_ok());
    let metadata = ServerBackupMetadata {
        endpoint_discovery_port: None,
        server_id,
        server_name: "Remote name".to_owned(),
        server_tunnel_address: profile.server_tunnel_address,
        wireguard_port: profile.endpoint.wireguard_port,
        server_wireguard_public_key: profile.server_wireguard_public_key.clone(),
        management_certificate_pem: profile.pinned_server_certificate_pem.clone(),
        dns_upstream: DnsUpstream::Recursive,
        private_dns_records: Vec::new(),
        ipv6_tunnel_enabled: false,
        obfuscated_udp: None,
        tcp_fallback: None,
        tls_like: None,
        endpoint_generation: 0,
    };
    assert!(server_backup_matches_profile(&metadata, &profile));
    let mut mismatch = metadata.clone();
    mismatch.server_id = ServerId::new();
    assert!(!server_backup_matches_profile(&mismatch, &profile));

    let mut restored = profile.clone();
    restored.endpoint.host = "203.0.113.99".to_owned();
    let migrated = restored_local_profile(&profile, &restored);
    assert_eq!(migrated.endpoint, restored.endpoint);
    assert_eq!(
        migrated.pending_previous_endpoint,
        Some(profile.endpoint.clone())
    );
    assert_eq!(migrated.endpoint_generation, profile.endpoint_generation);
    assert_eq!(migrated.identity_reference, profile.identity_reference);
    assert_eq!(
        migrated.client_management_certificate_pem,
        profile.client_management_certificate_pem
    );

    let recovered_in_place = restored_local_profile(&profile, &profile);
    assert_eq!(recovered_in_place.pending_previous_endpoint, None);
    restore.profile.role = ServerRole::Member;
    assert!(matches!(
        validate_server_restore_request(&restore),
        Err(InstallerError::InvalidInput(_))
    ));

    let request = InstallRequest {
        server_id,
        server_name: profile.name,
        target: restore.target,
        server_binary: restore.server_binary,
        identity: owner.public,
        identity_reference: profile.identity_reference,
        transport: crate::TransportSetup {
            wireguard_port: 51_820,
            ..Default::default()
        },
        dns_upstream: DnsUpstream::Recursive,
        private_dns_records: Vec::new(),
        replace_existing_installation: true,
    };
    let discovery = ServerDiscovery {
        os_id: "debian".into(),
        os_version: "13".into(),
        architecture: "x86_64".into(),
        default_interface: "eth0".into(),
        ipv6_default_interface: None,
        ssh_server_port: 22,
        ipv4_available: true,
        ipv6_available: false,
        nftables_available: true,
        wireguard_available: true,
        unbound_installed: true,
        sirinvpn_installed: true,
    };
    let script = install_script(
        &request,
        &discovery,
        "/tmp/staged/sirinvpn-server",
        "/tmp/staged/owner.crt",
        "restore",
        script_transaction("10.77.0.9", false, true),
    );
    let backup_position = script.find("tar -C / -cpf").unwrap();
    let guard_position = script
        .find(
            r#"systemctl enable --now "$ROLLBACK_SERVICE-boot.service" "$ROLLBACK_SERVICE.timer""#,
        )
        .unwrap();
    let replacement_position = script
        .find("# Explicit SSH-authorized SirinVPN identity replacement.")
        .unwrap();
    let restore_position = script.find(" restore-state ").unwrap();
    let initialization_position = script
        .find("/usr/local/lib/sirinvpn/sirinvpn-server init ")
        .unwrap();
    assert!(guard_position < backup_position);
    assert!(guard_position < replacement_position);
    assert!(replacement_position < restore_position);
    assert!(restore_position < initialization_position);
    assert!(script.contains("exec 3<&0\nexec </dev/null"));
    assert!(script.contains("restore-state --server-id"));
    assert!(script.contains("--owner-certificate /etc/sirinvpn/owner.crt <&3"));
    assert!(script.contains("allowed-ips 10.77.0.9/32"));
    assert!(!script.contains("correct horse battery staple"));
    assert!(!script.contains("snapshot-private-material"));
    assert!(
        std::process::Command::new("/bin/sh")
            .arg("-n")
            .arg("-c")
            .arg(&script)
            .status()
            .unwrap()
            .success(),
        "generated restore script must be valid POSIX shell"
    );
    assert!(ensure_restore_ipv6_compatible(true, false).is_err());
    assert!(ensure_restore_ipv6_compatible(true, true).is_ok());
    assert!(ensure_restore_ipv6_compatible(false, false).is_ok());
}

#[test]
fn uninstall_is_guarded_and_scoped_to_sirinvpn_state() {
    let script = uninstall_script("uninstall");
    let backup_position = script.find("tar -C / -cpf").unwrap();
    let guard_position = script
        .find(
            r#"systemctl enable --now "$ROLLBACK_SERVICE-boot.service" "$ROLLBACK_SERVICE.timer""#,
        )
        .unwrap();
    let protected_actions = &script[guard_position..];
    let stop_position = protected_actions
        .find("for unit in sirinvpn-server sirinvpn-doh sirinvpn-firewall sirinvpn-network")
        .unwrap();
    let removal_position = protected_actions
        .find("for path in $MANAGED_PATHS")
        .unwrap();

    assert!(guard_position < backup_position);
    assert!(stop_position < removal_position);
    assert!(script.contains(&format!(
        "MANAGED_PATHS=\"{MANAGED_SERVER_PATHS} {} var/lib/sirinvpn-server-release\"",
        crate::updates::UPDATE_MANAGED_PATHS
    )));
    assert!(script.contains("/etc/sirinvpn/firewall.sh down"));
    assert!(script.contains("/etc/sirinvpn/network.sh down"));
    assert!(script.contains("OnActiveSec=5min"));
    assert!(script.contains("tar -C / -xpf"));
    assert!(script.contains(r#"systemctl disable "$ROLLBACK_SERVICE.timer""#));
    assert!(script.contains(r#"systemctl reset-failed "$ROLLBACK_SERVICE.timer""#));
    assert!(!script.contains("apt-get"));
    assert!(!script.contains("iptables -F"));
    assert!(!script.contains("iptables -P"));
    assert!(!script.contains("flush ruleset"));
    assert!(
        std::process::Command::new("/bin/sh")
            .arg("-n")
            .arg("-c")
            .arg(&script)
            .status()
            .unwrap()
            .success(),
        "generated uninstall script must be valid POSIX shell"
    );

    let verification = uninstall_verification_command();
    assert!(verification.contains("--comment sirinvpn-forward-"));
    assert!(verification.contains("--comment sirinvpn-forward6-"));
    assert!(verification.contains("sirinvpn_filter"));
    assert!(verification.contains("sirinvpn_nat"));
    assert!(verification.contains("sirinvpn_nat6"));
    assert!(verification.contains("sirinvpn0"));
    assert!(verification.contains("systemctl is-enabled --quiet"));
    assert!(verification.contains("sirinvpn-doh"));
    assert!(verification.contains(&format!("127.0.0.1:{DOH_PROXY_PORT}")));
    assert!(!verification.contains("flush ruleset"));
    assert!(
        std::process::Command::new("/bin/sh")
            .arg("-n")
            .arg("-c")
            .arg(&verification)
            .status()
            .unwrap()
            .success(),
        "generated uninstall verification must be valid POSIX shell"
    );

    let commit = uninstall_commit_command("uninstall");
    assert!(commit.contains("set -eu"));
    assert!(
        commit.find(": >\"$BACKUP_DIR/committed\"").unwrap()
            < commit.find("cleanup_transaction\n").unwrap_or(commit.len())
    );
    assert!(commit.contains("userdel sirinvpn"));
    assert!(commit.contains(r#"systemctl reset-failed "$ROLLBACK_SERVICE.timer""#));
    assert!(
        std::process::Command::new("/bin/sh")
            .arg("-n")
            .arg("-c")
            .arg(&commit)
            .status()
            .unwrap()
            .success(),
        "generated uninstall commit must be valid POSIX shell"
    );
}
