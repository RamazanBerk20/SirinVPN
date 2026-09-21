use super::*;

fn discovery() -> ServerDiscovery {
    ServerDiscovery {
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
        unbound_installed: false,
        sirinvpn_installed: false,
    }
}

fn output(
    addresses: serde_json::Value,
    routes: serde_json::Value,
    links: serde_json::Value,
    listeners: &str,
    wireguard: &str,
) -> String {
    [
        ("ssh", "10.2.0.4".to_owned()),
        ("addresses", addresses.to_string()),
        ("routes", routes.to_string()),
        ("links", links.to_string()),
        ("listeners", listeners.into()),
        ("wireguard", wireguard.into()),
        (
            "nftables",
            r#"{"nftables":[{"table":{"name":"provider","family":"inet"}}]}"#.into(),
        ),
        ("firewall_services", "docker".into()),
        ("legacy_policies", "-P FORWARD DROP".into()),
        ("end", "".into()),
    ]
    .into_iter()
    .map(|(name, value)| format!("\x1e{name}\n{value}\n"))
    .collect()
}

#[test]
fn public_nat_and_private_addresses_have_distinct_actionable_reports() {
    let assigned = serde_json::json!([{"ifname":"eth0","addr_info":[{"local":"8.8.8.8","prefixlen":24},{"local":"10.2.0.4","prefixlen":24}]}]);
    let raw = output(
        assigned,
        serde_json::json!([]),
        serde_json::json!([]),
        "",
        "",
    );
    for (ip, expected) in [
        ("8.8.8.8", AddressExposure::PublicInterface),
        ("9.9.9.9", AddressExposure::NatOrProxy),
        ("10.2.0.4", AddressExposure::PrivateEndpoint),
    ] {
        let report = analyze(
            &discovery(),
            ip,
            vec![ip.parse().unwrap()],
            required_ports(&TransportSetup::default(), Some(7443)),
            &raw,
        )
        .unwrap();
        assert_eq!(report.exposure, expected);
        assert!(report.can_install());
        assert_eq!(report.ssh_local_address, Some("10.2.0.4".parse().unwrap()));
        assert_eq!(report.required_ports.len(), 4);
        assert!(
            report
                .issues
                .iter()
                .any(|issue| issue.code == "existing_firewall")
        );
        assert!(
            report
                .issues
                .iter()
                .any(|issue| issue.code == "firewall_drop_policy")
        );
    }
}

#[test]
fn occupied_ports_are_protocol_specific_and_preserve_managed_listeners() {
    let raw = output(
        serde_json::json!([]),
        serde_json::json!([]),
        serde_json::json!([]),
        "tcp LISTEN 0 128 0.0.0.0:443 0.0.0.0:* users:((\"nginx\",pid=1,fd=4))\n\
         udp UNCONN 0 0 0.0.0.0:51820 0.0.0.0:*\n\
         tcp LISTEN 0 128 [::]:7443 [::]:* users:((\"sirinvpn-server\",pid=5,fd=3))",
        "sirinvpn0\t51820",
    );
    let mut discovery = discovery();
    discovery.sirinvpn_installed = true;
    let ports = required_ports(&TransportSetup::default(), Some(7443));
    let report = analyze(
        &discovery,
        "8.8.8.8",
        vec!["8.8.8.8".parse().unwrap()],
        ports,
        &raw,
    )
    .unwrap();
    let blocked = report
        .issues
        .iter()
        .filter(|issue| issue.blocking)
        .collect::<Vec<_>>();
    assert_eq!(blocked.len(), 1);
    assert!(blocked[0].message.starts_with("TCP port 443"));
    assert!(report.require_compatible().is_err());
    discovery.ssh_server_port = 7443;
    let report = analyze(
        &discovery,
        "8.8.8.8",
        vec!["8.8.8.8".parse().unwrap()],
        required_ports(&TransportSetup::default(), Some(7443)),
        &raw,
    )
    .unwrap();
    assert!(
        report
            .issues
            .iter()
            .any(|issue| issue.code == "ssh_port_conflict")
    );
}

#[test]
fn specific_route_conflicts_block_while_broader_private_routes_remain_reviewable() {
    let raw = output(
        serde_json::json!([]),
        serde_json::json!([
        {"dst":"default","dev":"eth0"}, {"dst":"10.0.0.0/8","dev":"eth0"},
        {"dst":"10.77.0.0/25","dev":"wg-other"}]),
        serde_json::json!([{"ifname":"wg-other","linkinfo":{"info_kind":"wireguard"}}]),
        "",
        "",
    );
    let report = analyze(
        &discovery(),
        "8.8.8.8",
        vec!["8.8.8.8".parse().unwrap()],
        required_ports(&TransportSetup::default(), None),
        &raw,
    )
    .unwrap();
    assert_eq!(
        report.issues.iter().filter(|issue| issue.blocking).count(),
        1
    );
    assert!(
        report
            .issues
            .iter()
            .any(|issue| issue.code == "existing_vpn")
    );
    assert!(
        report
            .issues
            .iter()
            .any(|issue| issue.code == "tunnel_route_conflict" && !issue.blocking)
    );
    assert!(sections(&(raw.clone() + "\x1eend\n")).is_err());
    assert!(sections(&raw.replace("\x1elisteners\n\n", "")).is_err());
    assert!(sections(&"x".repeat(512 * 1024 + 1)).is_err());
}

#[test]
fn inspection_is_valid_shell_and_contains_only_local_discovery_commands() {
    let script = inspection_command(&required_ports(&TransportSetup::default(), Some(7443)));
    assert!(
        std::process::Command::new("sh")
            .args(["-n", "-c", &script])
            .status()
            .unwrap()
            .success()
    );
    assert!(script.contains("sport = :7443"));
    assert!(!script.contains("curl"));
    assert!(!script.contains("systemctl stop"));
    assert!(!script.contains("ip link add"));
}

#[test]
fn private_management_and_dns_conflicts_do_not_override_existing_resolvers() {
    let raw = output(
        serde_json::json!([]),
        serde_json::json!([]),
        serde_json::json!([]),
        "udp UNCONN 0 0 127.0.0.53:53 0.0.0.0:* users:((\"systemd-resolved\",pid=1,fd=4))\n\
         tcp LISTEN 0 128 0.0.0.0:8443 0.0.0.0:* users:((\"other-api\",pid=2,fd=4))\n\
         udp UNCONN 0 0 127.0.0.1:53 0.0.0.0:* users:((\"unbound\",pid=3,fd=4))",
        "",
    );
    let mut discovery = discovery();
    discovery.unbound_installed = true;
    let report = analyze(
        &discovery,
        "8.8.8.8",
        vec!["8.8.8.8".parse().unwrap()],
        required_ports(&TransportSetup::default(), None),
        &raw,
    )
    .unwrap();
    let blocked = report
        .issues
        .iter()
        .filter(|issue| issue.blocking)
        .collect::<Vec<_>>();
    assert_eq!(blocked.len(), 1);
    assert!(blocked[0].message.contains("management API"));
}

#[test]
#[ignore = "requires disposable networking; use tests/network/run-installer-preflight.sh"]
fn kernel_preflight_reads_real_addresses_routes_and_listeners_without_modification() {
    assert_eq!(
        std::env::var("SIRINVPN_POLICY_ISOLATED").as_deref(),
        Ok("1")
    );
    assert!(Path::new("/.dockerenv").exists());
    let run = |program: &str, args: &[&str]| {
        let output = std::process::Command::new(program)
            .args(args)
            .output()
            .unwrap();
        assert!(output.status.success(), "{program} failed");
        output.stdout
    };
    let links: serde_json::Value =
        serde_json::from_slice(&run("ip", &["-j", "link", "show"])).unwrap();
    assert_eq!(links.as_array().unwrap().len(), 1);
    run("ip", &["link", "set", "lo", "up"]);
    run("ip", &["link", "add", "eth0", "type", "dummy"]);
    run("ip", &["address", "add", "10.2.0.4/24", "dev", "eth0"]);
    run("ip", &["link", "set", "eth0", "up"]);
    run("ip", &["route", "add", "10.77.0.0/24", "dev", "eth0"]);
    let listener = std::net::TcpListener::bind("0.0.0.0:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let transport = TransportSetup {
        tcp_tls_port: port,
        ..Default::default()
    };
    let ports = required_ports(&transport, Some(7443));
    let before = run("ip", &["-j", "address", "show"]);
    let raw = run("sh", &["-c", &inspection_command(&ports)]);
    let report = analyze(
        &discovery(),
        "8.8.8.8",
        vec!["8.8.8.8".parse().unwrap()],
        ports,
        std::str::from_utf8(&raw).unwrap(),
    )
    .unwrap();
    assert_eq!(report.exposure, AddressExposure::NatOrProxy);
    assert!(
        report
            .issues
            .iter()
            .any(|issue| issue.code == "port_in_use" && issue.blocking)
    );
    assert!(
        report
            .issues
            .iter()
            .any(|issue| issue.code == "tunnel_route_conflict" && issue.blocking)
    );
    assert_eq!(run("ip", &["-j", "address", "show"]), before);
}
