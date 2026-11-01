use super::*;

const IPV6_ONLY: &str = "os_id=debian\nos_version=13\narchitecture=x86_64\ndefault_interface=\nipv6_default_interface=enp1s0\nssh_server_port=22\nipv4_available=0\nipv6_available=1\nnftables_available=1\nwireguard_available=1\nunbound_installed=0\nsirinvpn_installed=0\n";

#[test]
fn an_ipv6_only_vps_uses_its_ipv6_uplink_as_the_external_interface() {
    let discovery = parse_discovery(IPV6_ONLY).unwrap();
    assert_eq!(discovery.default_interface, "enp1s0");
    assert_eq!(discovery.ipv6_default_interface.as_deref(), Some("enp1s0"));
    assert!(!discovery.ipv4_available);
    assert!(check_compatibility(&discovery).is_ok());

    // Neither family routes to the Internet: nothing to forward members to.
    let isolated = IPV6_ONLY
        .replace("ipv6_default_interface=enp1s0", "ipv6_default_interface=")
        .replace("ipv6_available=1", "ipv6_available=0");
    assert!(parse_discovery(&isolated).is_err());
    // A link-local-only IPv6 route is not a usable uplink either.
    assert!(parse_discovery(&IPV6_ONLY.replace("ipv6_available=1", "ipv6_available=0")).is_err());
}

#[test]
fn ssh_connects_to_an_unbracketed_ipv6_literal() {
    // A host without IPv6 loopback cannot run this check.
    let Ok(listener) = std::net::TcpListener::bind("[::1]:0") else {
        return;
    };
    let port = listener.local_addr().unwrap().port();
    let accepted = std::thread::spawn(move || listener.accept().unwrap().1);
    let target = SshTarget {
        host: "::1".into(),
        port,
        username: "root".into(),
        authentication: SshAuthentication::Agent,
        sudo_password: None,
        expected_host_key_sha256: None,
    };
    // Nothing speaks SSH there; the point is that the literal resolved and connected.
    assert!(connect_transport(&target).is_err());
    assert!(accepted.join().unwrap().is_ipv6());
}

#[test]
fn an_ipv6_only_vps_needs_ipv6_secure_dns_and_no_recursion() {
    let ipv6_only = stack(false, true);
    let refused = |policy: &DnsUpstream| match ensure_dns_upstream_compatible(policy, &ipv6_only) {
        Err(InstallerError::Incompatible(message)) => message,
        other => panic!("{other:?}"),
    };
    assert!(refused(&DnsUpstream::Recursive).contains("recursively"));
    let mixed = DnsUpstream::DnsOverTls {
        endpoints: vec![
            "9.9.9.9#dns.quad9.net".parse().unwrap(),
            "2620:fe::fe#dns.quad9.net".parse().unwrap(),
        ],
    };
    assert!(refused(&mixed).contains("IPv6 addresses"));
    let doh = DnsUpstream::DnsOverHttps {
        endpoints: vec!["1.1.1.1#cloudflare-dns.com/dns-query".parse().unwrap()],
    };
    assert!(refused(&doh).contains("IPv6 addresses"));

    let quad9 = DnsUpstream::DnsOverTls {
        endpoints: vec!["2620:fe::fe#dns.quad9.net".parse().unwrap()],
    };
    assert!(ensure_dns_upstream_compatible(&quad9, &ipv6_only).is_ok());
    // Private zone servers may be reached through a subnet route, so IPv4 stays allowed there.
    let split = DnsUpstream::Split {
        default: Box::new(quad9.clone()),
        zones: vec!["corp.home=192.168.1.53".parse().unwrap()],
    };
    assert!(ensure_dns_upstream_compatible(&split, &ipv6_only).is_ok());
    let secure_ipv4_zone = DnsUpstream::Split {
        default: Box::new(quad9.clone()),
        zones: vec!["corp.home=192.0.2.53#resolver.corp.home".parse().unwrap()],
    };
    assert!(refused(&secure_ipv4_zone).contains("IPv6 addresses"));
    let split_recursive = DnsUpstream::Split {
        default: Box::new(DnsUpstream::Recursive),
        zones: vec!["corp.home=192.168.1.53".parse().unwrap()],
    };
    assert!(refused(&split_recursive).contains("recursively"));
    // A dual-stack VPS keeps every policy it accepted before.
    assert!(ensure_dns_upstream_compatible(&DnsUpstream::Recursive, &stack(true, true)).is_ok());
    assert!(ensure_dns_upstream_compatible(&mixed, &stack(true, true)).is_ok());
}

#[test]
fn nat64_prefixes_are_unicast_96s_and_only_for_a_vps_without_ipv4() {
    for (text, expected) in [
        ("64:ff9b::/96", "64:ff9b::"),
        (" 2a00:1098:2b::/96 ", "2a00:1098:2b::"),
        ("2001:db8:64::", "2001:db8:64::"),
    ] {
        assert_eq!(
            parse_nat64_prefix(text).unwrap(),
            expected.parse::<Ipv6Addr>().unwrap()
        );
    }
    for text in [
        "64:ff9b::1/96",
        "64:ff9b::/64",
        "64:ff9b::/9",
        "ff02::/96",
        "fe80::/96",
        "::/96",
        "::1",
        "::ffff:0:0/96",
        "192.0.2.1",
        "",
    ] {
        assert!(parse_nat64_prefix(text).is_err(), "{text}");
    }
    let prefix = Some("64:ff9b::".parse().unwrap());
    assert!(ensure_nat64_compatible(prefix, &stack(false, true)).is_ok());
    assert!(ensure_nat64_compatible(None, &stack(false, true)).is_ok());
    assert!(matches!(
        ensure_nat64_compatible(prefix, &stack(true, true)),
        Err(InstallerError::Incompatible(message)) if message.contains("NAT64 off")
    ));
}

#[test]
fn an_ipv6_only_install_routes_members_out_of_the_ipv6_uplink_with_optional_dns64() {
    let identity = new_identity_for_server("Six").unwrap();
    let mut request = InstallRequest {
        server_id: ServerId::new(),
        server_name: "Six".into(),
        target: SshTarget {
            host: "2001:db8::4".into(),
            port: 22,
            username: "root".into(),
            authentication: SshAuthentication::Agent,
            sudo_password: None,
            expected_host_key_sha256: Some("SHA256:test".into()),
        },
        server_binary: PathBuf::from("/tmp/server").into(),
        identity: identity.public.clone(),
        identity_reference: "id".into(),
        transport: crate::TransportSetup::default(),
        dns_upstream: DnsUpstream::DnsOverTls {
            endpoints: vec!["2620:fe::fe#dns.quad9.net".parse().unwrap()],
        },
        private_dns_records: Vec::new(),
        nat64_prefix: None,
        replace_existing_installation: false,
    };
    let discovery = parse_discovery(IPV6_ONLY).unwrap();
    let script = |request: &InstallRequest| {
        install_script(
            request,
            &discovery,
            "/tmp/server",
            "/tmp/owner",
            "nonce",
            script_transaction("10.77.0.2", true, false),
        )
    };
    let without_nat64 = script(&request);
    assert!(without_nat64.contains("--public-host '2001:db8::4'"));
    assert!(without_nat64.contains(r#""external_interface":"enp1s0""#));
    assert!(
        without_nat64.contains(r#"iifname "sirinvpn0" meta nfproto ipv6 oifname "enp1s0" accept"#)
    );
    assert!(without_nat64.contains(r#"oifname "enp1s0" masquerade"#));
    assert!(without_nat64.contains("forward-addr: 2620:fe::fe@853#dns.quad9.net"));
    assert!(!without_nat64.contains("dns64"));
    // Run the generated checks against real files, under `set -e` as the installer does.
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("sirinvpn.conf");
    let verify = |prefix: Option<Ipv6Addr>, configuration: &str| {
        fs::write(&path, configuration).unwrap();
        let check = unbound_dns64_verification(prefix).replace(
            "/etc/unbound/unbound.conf.d/sirinvpn.conf",
            path.to_str().unwrap(),
        );
        std::process::Command::new("/bin/sh")
            .arg("-c")
            .arg(format!("set -eu\n{check}\ntrue"))
            .status()
            .unwrap()
            .success()
    };
    let unbound = |script: &str| {
        let start = script.find("sirinvpn.conf <<'UNBOUND'\n").unwrap();
        script[start..start + script[start..].find("\nUNBOUND\n").unwrap()].to_owned()
    };
    let private_record = "  local-zone: \"dns64.home.\" static\n";
    assert!(verify(None, &(unbound(&without_nat64) + private_record)));

    request.nat64_prefix = Some("2a00:1098:2b::".parse().unwrap());
    let with_nat64 = script(&request);
    assert!(with_nat64.contains(
        "  module-config: \"dns64 validator iterator\"\n  dns64-prefix: 2a00:1098:2b::/96\n"
    ));
    // Inside the server: section, before any forward-zone.
    assert!(with_nat64.find("dns64-prefix").unwrap() < with_nat64.find("forward-zone:").unwrap());
    assert!(verify(request.nat64_prefix, &unbound(&with_nat64)));
    assert!(!verify(None, &unbound(&with_nat64)));
    assert!(!verify(request.nat64_prefix, &unbound(&without_nat64)));
    assert!(!verify(
        Some("64:ff9b::".parse().unwrap()),
        &unbound(&with_nat64)
    ));
}

#[test]
#[ignore = "requires disposable networking and Unbound; use tests/network/run-ipv6-only.sh"]
fn kernel_ipv6_only_vps_forwards_members_over_ipv6_and_reaches_ipv4_names_through_nat64() {
    assert_eq!(
        std::env::var("SIRINVPN_POLICY_ISOLATED").as_deref(),
        Ok("1")
    );
    assert!(Path::new("/.dockerenv").exists());
    let identity = new_identity_for_server("Six").unwrap();
    let server_id = ServerId::new();
    let request = InstallRequest {
        server_id,
        server_name: "Six".into(),
        target: SshTarget {
            host: "2001:db8:1::2".into(),
            port: 22,
            username: "root".into(),
            authentication: SshAuthentication::Agent,
            sudo_password: None,
            expected_host_key_sha256: Some("SHA256:test".into()),
        },
        server_binary: PathBuf::from("/tmp/server").into(),
        identity: identity.public.clone(),
        identity_reference: "id".into(),
        transport: crate::TransportSetup::default(),
        dns_upstream: DnsUpstream::DnsOverTls {
            endpoints: vec!["2001:db8:2::53#resolver.fixture".parse().unwrap()],
        },
        private_dns_records: Vec::new(),
        nat64_prefix: Some("64:ff9b::".parse().unwrap()),
        replace_existing_installation: false,
    };
    let discovery = parse_discovery(&IPV6_ONLY.replace("enp1s0", "vps-up")).unwrap();
    ensure_dns_upstream_compatible(&request.dns_upstream, &discovery).unwrap();
    ensure_nat64_compatible(request.nat64_prefix, &discovery).unwrap();
    let script = install_script(
        &request,
        &discovery,
        "/tmp/server",
        "/tmp/owner",
        "nonce",
        script_transaction("10.77.0.2", true, false),
    );
    let heredoc = |opening: &str, end: &str| {
        let start = script.find(opening).unwrap() + opening.len();
        script[start..start + script[start..].find(end).unwrap()].to_owned()
    };
    let address = |host| ipv6_tunnel_address(server_id, Ipv4Addr::new(10, 77, 0, host)).unwrap();
    let lab = serde_json::json!({
        "nftables": heredoc("/etc/sirinvpn/nftables.conf <<'NFTABLES'\n", "\nNFTABLES\n"),
        "unbound": heredoc("/etc/unbound/unbound.conf.d/sirinvpn.conf <<'UNBOUND'\n", "\nUNBOUND\n"),
        "server_ipv6": address(1),
        "member_ipv6": address(2),
        "ipv6_cidr": ipv6_tunnel_cidr(server_id),
    });
    let mut child = std::process::Command::new("python3")
        .arg("tests/network/ipv6_only_vps.py")
        .stdin(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(lab.to_string().as_bytes())
        .unwrap();
    assert!(child.wait().unwrap().success());
}
