use super::*;

#[test]
fn shell_quoting_does_not_allow_substitution() {
    assert_eq!(shell_quote("a'b"), "'a'\"'\"'b'");
    assert_eq!(shell_quote("$(reboot)"), "'$(reboot)'");
}

#[test]
fn https_init_arguments_pass_cdn_mode_only_when_on() {
    let mut setup = TransportSetup {
        https: Some(sirinvpn_protocol::HttpsTransport {
            server_name: "vpn.example.org".into(),
            path: "/connect".into(),
            cdn: false,
        }),
        ..Default::default()
    };
    let direct = setup.init_arguments();
    assert!(direct.contains(" --https-server-name 'vpn.example.org' --https-path '/connect'"));
    assert!(!direct.contains("--https-cdn"));
    setup.https.as_mut().unwrap().cdn = true;
    assert!(
        setup
            .init_arguments()
            .contains(" --https-path '/connect' --https-cdn")
    );
    setup.validate().unwrap();
    // A proxied name cannot also be an address devices reach directly.
    setup.alternate_endpoint_hosts = vec!["VPN.example.org".into()];
    assert!(setup.validate().is_err());
}

#[test]
fn in_memory_ssh_keys_are_bounded_and_redacted() {
    let marker = "PRIVATE-KEY-SECRET-MARKER";
    let authentication = SshAuthentication::PrivateKeyMemory {
        private_key_pem: Zeroizing::new(marker.to_owned()),
        passphrase: Some(Zeroizing::new("passphrase-marker".to_owned())),
    };
    let rendered = format!("{authentication:?}");
    assert!(!rendered.contains(marker));
    assert!(!rendered.contains("passphrase-marker"));

    let mut target = SshTarget {
        host: "203.0.113.4".to_owned(),
        port: 22,
        username: "root".to_owned(),
        authentication,
        sudo_password: None,
        expected_host_key_sha256: Some(
            "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
        ),
    };
    assert!(validate_target(&target).is_ok());
    target.authentication = SshAuthentication::PrivateKeyMemory {
        private_key_pem: Zeroizing::new("x".repeat(64 * 1024 + 1)),
        passphrase: None,
    };
    assert!(matches!(
        validate_target(&target),
        Err(InstallerError::InvalidInput(_))
    ));
}

#[test]
fn dns_over_tls_configuration_is_authenticated_and_has_no_plaintext_fallback() {
    let dns_upstream = DnsUpstream::DnsOverTls {
        endpoints: vec![
            "1.1.1.1#one.one.one.one".parse().unwrap(),
            "2606:4700:4700::1111#one.one.one.one".parse().unwrap(),
        ],
    };
    let arguments = server_dns_init_arguments(&dns_upstream, &[]);
    assert!(arguments.contains("--dns-over-tls-endpoint '1.1.1.1#one.one.one.one'"));
    assert!(arguments.contains("--dns-over-tls-endpoint '2606:4700:4700::1111#one.one.one.one'"));

    let (server, forwarding) = unbound_dns_configuration(&dns_upstream, &[]);
    assert!(server.contains("tls-cert-bundle"));
    assert!(forwarding.contains("forward-tls-upstream: yes"));
    assert!(forwarding.contains("forward-first: no"));
    assert!(!forwarding.contains("forward-first: yes"));
    assert!(forwarding.contains("forward-addr: 1.1.1.1@853#one.one.one.one"));
    assert!(forwarding.contains("forward-addr: 2606:4700:4700::1111@853#one.one.one.one"));

    let verification = unbound_dns_verification(&dns_upstream, &[]);
    assert!(verification.contains("unbound.conf.d/sirinvpn.conf"));
    assert!(verification.contains("forward-first: no"));
    assert!(verification.contains("-eq 2"));

    assert_eq!(
        server_dns_init_arguments(&DnsUpstream::Recursive, &[]),
        " --recursive-dns --clear-private-dns-records"
    );
    let (server, forwarding) = unbound_dns_configuration(&DnsUpstream::Recursive, &[]);
    assert!(server.is_empty());
    assert!(forwarding.is_empty());
    assert!(ensure_dns_upstream_compatible(&DnsUpstream::Recursive, &stack(true, false)).is_ok());
    assert!(
        ensure_dns_upstream_compatible(
            &DnsUpstream::DnsOverTls {
                endpoints: vec!["1.1.1.1#one.one.one.one".parse().unwrap()],
            },
            &stack(true, false),
        )
        .is_ok()
    );
    assert!(ensure_dns_upstream_compatible(&dns_upstream, &stack(true, false)).is_err());
    assert!(ensure_dns_upstream_compatible(&dns_upstream, &stack(true, true)).is_ok());
}

#[test]
fn dns_over_https_uses_a_pinned_loopback_proxy_and_scoped_service() {
    let dns_upstream = DnsUpstream::DnsOverHttps {
        endpoints: vec![
            "1.1.1.1#cloudflare-dns.com/dns-query".parse().unwrap(),
            "2606:4700:4700::1111#cloudflare-dns.com/dns-query"
                .parse()
                .unwrap(),
        ],
    };
    let arguments = server_dns_init_arguments(&dns_upstream, &[]);
    assert!(arguments.contains("--dns-over-https-endpoint '1.1.1.1#cloudflare-dns.com/dns-query'"));
    assert!(
        arguments.contains(
            "--dns-over-https-endpoint '2606:4700:4700::1111#cloudflare-dns.com/dns-query'"
        )
    );

    let (server, forwarding) = unbound_dns_configuration(&dns_upstream, &[]);
    assert_eq!(server, "  do-not-query-localhost: no");
    assert!(forwarding.contains("forward-first: no"));
    assert!(forwarding.contains(&format!("forward-addr: 127.0.0.1@{DOH_PROXY_PORT}")));
    assert!(!forwarding.contains("forward-tls-upstream"));
    let verification = unbound_dns_verification(&dns_upstream, &[]);
    assert!(verification.contains("do-not-query-localhost: no"));
    assert!(verification.contains(&format!("127.0.0.1@{DOH_PROXY_PORT}")));
    assert!(verification.contains("-eq 1"));
    assert!(ensure_dns_upstream_compatible(&dns_upstream, &stack(true, false)).is_err());
    assert!(ensure_dns_upstream_compatible(&dns_upstream, &stack(true, true)).is_ok());

    let identity = new_identity_for_server("DoH Test").unwrap();
    let request = InstallRequest {
        server_id: ServerId::new(),
        server_name: "DoH Test".into(),
        target: SshTarget {
            host: "203.0.113.4".into(),
            port: 22,
            username: "root".into(),
            authentication: SshAuthentication::Agent,
            sudo_password: None,
            expected_host_key_sha256: Some("SHA256:test".into()),
        },
        server_binary: PathBuf::from("/tmp/server").into(),
        identity: identity.public,
        identity_reference: "id".into(),
        transport: crate::TransportSetup {
            wireguard_port: 51_820,
            ..Default::default()
        },
        dns_upstream: dns_upstream.clone(),
        private_dns_records: Vec::new(),
        nat64_prefix: None,
        replace_existing_installation: false,
    };
    let discovery = ServerDiscovery {
        os_id: "debian".into(),
        os_version: "13".into(),
        architecture: "x86_64".into(),
        default_interface: "eth0".into(),
        ipv6_default_interface: Some("eth0".into()),
        ssh_server_port: 22,
        ssh_local_address: None,
        ipv4_available: true,
        ipv6_available: true,
        nftables_available: true,
        wireguard_available: true,
        unbound_installed: true,
        sirinvpn_installed: true,
    };
    let script = install_script(
        &request,
        &discovery,
        "/tmp/server",
        "/tmp/owner",
        "doh",
        script_transaction("10.77.0.2", true, false),
    );
    assert!(script.contains("ExecStart=/usr/local/lib/sirinvpn/sirinvpn-server doh-proxy"));
    assert!(script.contains("IPAddressDeny=any"));
    assert!(script.contains("IPAddressAllow=127.0.0.1"));
    assert!(script.contains("IPAddressAllow=1.1.1.1"));
    assert!(script.contains("IPAddressAllow=2606:4700:4700::1111"));
    assert!(script.contains("Requires=sirinvpn-network.service sirinvpn-doh.service"));
    assert!(script.contains("systemctl enable sirinvpn-doh"));
    assert!(script.contains("systemctl restart sirinvpn-doh"));
    assert!(script.contains(&format!("loopback port {DOH_PROXY_PORT}")));
    assert!(script.contains("StandardOutput=null\nStandardError=null"));
    assert!(
        std::process::Command::new("/bin/sh")
            .arg("-n")
            .arg("-c")
            .arg(&script)
            .status()
            .unwrap()
            .success(),
        "generated DNS-over-HTTPS installer script must be valid POSIX shell"
    );
}

#[test]
fn private_dns_records_are_rendered_and_verified_exactly() {
    let records = vec![
        "nas.home=10.20.30.40".parse().unwrap(),
        "nas.home=fd00::20".parse().unwrap(),
        "server.home=10.20.30.50".parse().unwrap(),
    ];
    let arguments = server_dns_init_arguments(&DnsUpstream::Recursive, &records);
    assert!(arguments.starts_with(" --recursive-dns"));
    assert!(arguments.contains("--private-dns-record 'nas.home=10.20.30.40'"));
    assert!(arguments.contains("--private-dns-record 'nas.home=fd00::20'"));

    let (server, forwarding) = unbound_dns_configuration(&DnsUpstream::Recursive, &records);
    assert!(forwarding.is_empty());
    assert_eq!(server.matches("local-zone:").count(), 2);
    assert_eq!(server.matches("local-data:").count(), 3);
    assert!(server.contains("local-zone: \"nas.home.\" static"));
    assert!(server.contains("local-data: \"nas.home. 60 IN A 10.20.30.40\""));
    assert!(server.contains("local-data: \"nas.home. 60 IN AAAA fd00::20\""));

    let verification = unbound_dns_verification(&DnsUpstream::Recursive, &records);
    assert!(verification.contains("grep -Fc '  local-zone: '"));
    assert!(verification.contains("-eq 2"));
    assert!(verification.contains("grep -Fc '  local-data: '"));
    assert!(verification.contains("-eq 3"));
    assert!(verification.contains("nas.home. 60 IN A 10.20.30.40"));

    let cleared = unbound_dns_verification(&DnsUpstream::Recursive, &[]);
    assert!(cleared.contains("if grep -Fq '  local-zone: ' "));
    assert!(cleared.contains("if grep -Fq '  local-data: ' "));
}

#[test]
fn identifies_supported_server_artifact_architectures() {
    let mut elf = [0_u8; 20];
    elf[..4].copy_from_slice(b"\x7fELF");
    elf[4] = 2;
    elf[5] = 1;
    elf[18..20].copy_from_slice(&62_u16.to_le_bytes());
    assert_eq!(elf_architecture(&elf), Some("x86_64"));
    elf[18..20].copy_from_slice(&183_u16.to_le_bytes());
    assert_eq!(elf_architecture(&elf), Some("aarch64"));
    elf[4] = 1;
    assert_eq!(elf_architecture(&elf), None);
}

#[test]
fn selects_packaged_server_artifact_after_vps_architecture_discovery() {
    let source = ServerBinarySource::by_architecture(
        PathBuf::from("/payloads/sirinvpn-server-x86_64"),
        PathBuf::from("/payloads/sirinvpn-server-aarch64"),
    );
    assert_eq!(
        source.path_for_architecture("x86_64").unwrap(),
        Path::new("/payloads/sirinvpn-server-x86_64")
    );
    assert_eq!(
        source.path_for_architecture("aarch64").unwrap(),
        Path::new("/payloads/sirinvpn-server-aarch64")
    );
    assert!(source.path_for_architecture("riscv64").is_err());

    let exact = ServerBinarySource::Exact(PathBuf::from("/payloads/custom-server"));
    assert_eq!(
        exact.path_for_architecture("aarch64").unwrap(),
        Path::new("/payloads/custom-server")
    );
}

#[test]
fn payload_support_reads_the_elf_machine_of_each_artifact() {
    let directory = tempfile::tempdir().unwrap();
    let mut elf = [0_u8; 64];
    elf[..6].copy_from_slice(b"\x7fELF\x02\x01");
    elf[18..20].copy_from_slice(&62_u16.to_le_bytes());
    let x86_64 = directory.path().join("x86_64");
    fs::write(&x86_64, elf).unwrap();
    let exact = ServerBinarySource::Exact(x86_64.clone());
    assert!(exact.supports("x86_64"));
    assert!(!exact.supports("aarch64"));
    let missing = directory.path().join("missing");
    let packaged = ServerBinarySource::by_architecture(x86_64, missing);
    assert!(packaged.supports("x86_64"));
    assert!(!packaged.supports("aarch64"));
}

#[test]
fn discovery_parser_rejects_an_unsafe_interface() {
    let input = "os_id=debian\nos_version=13\narchitecture=x86_64\ndefault_interface=eth0;reboot\nipv6_default_interface=\nssh_server_port=22\nipv4_available=1\nipv6_available=0\nnftables_available=1\nwireguard_available=1\nunbound_installed=1\nsirinvpn_installed=0\n";
    assert!(parse_discovery(input).is_err());
}

#[test]
fn discovery_parser_binds_ipv6_availability_to_a_safe_default_interface() {
    let ipv4_only = "os_id=debian\nos_version=13\narchitecture=x86_64\ndefault_interface=eth0\nipv6_default_interface=\nssh_server_port=22\nipv4_available=1\nipv6_available=0\nnftables_available=1\nwireguard_available=1\nunbound_installed=1\nsirinvpn_installed=0\n";
    let parsed = parse_discovery(ipv4_only).unwrap();
    assert!(!parsed.ipv6_available);
    assert_eq!(parsed.ipv6_default_interface, None);
    assert_eq!(parsed.ssh_local_address, None);
    let with_ssh_address = ipv4_only.replace(
        "ssh_server_port=22\n",
        "ssh_server_port=22\nssh_local_address=10.2.0.4\n",
    );
    assert_eq!(
        parse_discovery(&with_ssh_address)
            .unwrap()
            .ssh_local_address,
        Some("10.2.0.4".parse().unwrap())
    );

    let dual_stack = ipv4_only
        .replace("ipv6_default_interface=\n", "ipv6_default_interface=ens6\n")
        .replace("ipv6_available=0", "ipv6_available=1");
    let parsed = parse_discovery(&dual_stack).unwrap();
    assert!(parsed.ipv6_available);
    assert_eq!(parsed.ipv6_default_interface.as_deref(), Some("ens6"));

    let missing_interface = ipv4_only.replace("ipv6_available=0", "ipv6_available=1");
    assert!(parse_discovery(&missing_interface).is_err());
    let unsafe_interface = dual_stack.replace("ens6", "ens6;reboot");
    assert!(parse_discovery(&unsafe_interface).is_err());
}

#[test]
fn compatibility_gate_accepts_debian_13_and_ubuntu_24_04_on_supported_architectures() {
    let debian = "os_id=debian\nos_version=13\narchitecture=x86_64\ndefault_interface=eth0\nipv6_default_interface=\nssh_server_port=22\nipv4_available=1\nipv6_available=0\nnftables_available=1\nwireguard_available=1\nunbound_installed=0\nsirinvpn_installed=0\n";
    // `. /etc/os-release` unquotes Ubuntu's VERSION_ID="24.04" for every 24.04.x point release.
    let ubuntu = debian.replace(
        "os_id=debian\nos_version=13",
        "os_id=ubuntu\nos_version=24.04",
    );
    for host in [debian, ubuntu.as_str()] {
        for architecture in ["x86_64", "aarch64"] {
            let discovery = parse_discovery(&host.replace("x86_64", architecture)).unwrap();
            assert!(check_compatibility(&discovery).is_ok());
        }
        let riscv = parse_discovery(&host.replace("x86_64", "riscv64")).unwrap();
        assert!(check_compatibility(&riscv).is_err());
    }
    for (os_id, os_version) in [
        ("debian", "12"),
        ("debian", "24.04"),
        ("ubuntu", "13"),
        ("ubuntu", "22.04"),
        ("ubuntu", "24.10"),
        ("ubuntu", "24.04.1"),
        ("linuxmint", "22"),
    ] {
        let mut discovery = parse_discovery(debian).unwrap();
        discovery.os_id = os_id.into();
        discovery.os_version = os_version.into();
        assert!(matches!(
            check_compatibility(&discovery),
            Err(InstallerError::Incompatible(message)) if message.contains("Ubuntu 24.04")
        ));
    }
}
