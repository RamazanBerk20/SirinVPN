use super::*;

#[test]
fn script_has_scoped_firewall_ownership_and_docker_interop() {
    let identity = new_identity_for_server("Test").unwrap();
    let request = InstallRequest {
        server_id: ServerId::new(),
        server_name: "Test".into(),
        target: SshTarget {
            host: "203.0.113.4".into(),
            port: 22,
            username: "root".into(),
            authentication: SshAuthentication::Agent,
            sudo_password: None,
            expected_host_key_sha256: Some("SHA256:test".into()),
        },
        server_binary: PathBuf::from("/tmp/server").into(),
        identity: identity.public.clone(),
        identity_reference: "id".into(),
        transport: crate::TransportSetup {
            wireguard_port: 51_820,
            ..Default::default()
        },
        dns_upstream: DnsUpstream::Recursive,
        private_dns_records: Vec::new(),
        replace_existing_installation: false,
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
        unbound_installed: false,
        sirinvpn_installed: false,
    };
    let script = install_script(
        &request,
        &discovery,
        "/tmp/server",
        "/tmp/owner",
        "nonce",
        script_transaction("10.77.0.2", false, false),
    );
    assert!(script.contains("table inet sirinvpn_filter"));
    assert!(script.contains("set peer_communication4"));
    assert!(script.contains("set peer_communication6"));
    assert!(script.contains("ip saddr @peer_communication4 ip daddr @peer_communication4 accept"));
    assert!(
        script.contains("ip6 saddr @peer_communication6 ip6 daddr @peer_communication6 accept")
    );
    assert!(script.contains("iifname \"sirinvpn0\" oifname \"sirinvpn0\" drop"));
    assert!(script.contains("isolate-runtime|isolate-peers)"));
    assert!(script.contains("ExecStopPost=+/etc/sirinvpn/firewall.sh isolate-runtime"));
    assert!(script.contains("flush chain inet sirinvpn_filter port_forward"));
    assert!(script.contains("flush chain ip sirinvpn_nat port_forward_prerouting"));
    assert!(script.contains("table ip sirinvpn_nat"));
    assert!(script.contains("chain port_forward_prerouting"));
    assert!(script.contains("priority dstnat - 10"));
    assert!(script.contains("jump port_forward"));
    assert!(script.contains("ct mark 0x5356504e drop"));
    assert!(script.contains("ct mark 0x5356504e masquerade"));
    assert!(script.contains("iifname \"eth0\" meta nfproto ipv4 oifname \"sirinvpn0\" drop"));
    let forward_chain = script.find("chain forward {").unwrap();
    let port_forward_jump = script[forward_chain..].find("jump port_forward").unwrap();
    let stale_forward_drop = script[forward_chain..]
        .find("ct mark 0x5356504e drop")
        .unwrap();
    let established_reply = script[forward_chain..]
        .find("ct state established,related accept")
        .unwrap();
    let unsolicited_drop = script[forward_chain..]
        .find("meta nfproto ipv4 oifname \"sirinvpn0\" drop")
        .unwrap();
    assert!(port_forward_jump < stale_forward_drop);
    assert!(stale_forward_drop < established_reply);
    assert!(established_reply < unsolicited_drop);
    assert!(script.contains("oifname \"eth0\""));
    assert!(!script.contains("oifname 'eth0'"));
    assert!(!script.contains("flush ruleset"));
    assert!(script.contains("iptables -w 5 -C DOCKER-USER"));
    assert!(script.contains("iptables -w 5 -I DOCKER-USER 1"));
    assert!(script.contains("iptables -w 5 -D DOCKER-USER"));
    assert!(script.contains("--comment sirinvpn-forward-out"));
    assert!(script.contains("--comment sirinvpn-forward-in"));
    assert!(script.contains("--comment sirinvpn-forward-peers"));
    assert!(script.contains("--comment sirinvpn-forward-ports"));
    assert!(script.contains("--comment sirinvpn-forward6-peers"));
    assert!(script.contains("After=sirinvpn-network.service docker.service"));
    assert!(!script.contains("iptables -P FORWARD"));
    assert!(!script.contains("iptables -F"));
    assert!(!script.contains("Explicit SSH-authorized SirinVPN identity replacement"));
    assert!(script.contains("OnActiveSec=5min"));
    assert!(script.contains("managed.tar"));
    assert!(script.contains("/run/sirinvpn-rollback-*.sh"));
    assert!(script.contains("tar -C / -xpf"));
    assert!(script.contains(r#"systemctl disable "$ROLLBACK_SERVICE.timer""#));
    assert!(script.contains(r#"systemctl reset-failed "$ROLLBACK_SERVICE.timer""#));
    assert!(script.contains("command -v wg"));
    assert!(script.contains("dns-root-data"));
    assert!(script.contains("if [ \"$#\" -gt 0 ]"));
    assert!(script.contains("--server-id"));
    assert!(script.contains("--owner-wireguard-public-key"));
    assert!(script.contains("if [ ! -e /etc/sirinvpn/authorization-required ] && [ ! -e /etc/sirinvpn/authorization/authorization.json ]; then\n      wg set sirinvpn0 peer"));
    assert!(script.contains("--obfuscated-udp-port 443"));
    assert!(script.contains("--tcp-fallback-port 443"));
    assert!(script.contains("--tls-like-port 443"));
    assert!(script.contains("udp dport 443 accept"));
    assert!(script.contains("tcp dport 443 accept"));
    assert!(script.contains("refusing to replace it"));
    assert!(script.contains("CAP_NET_BIND_SERVICE"));
    assert!(script.contains("/etc/sirinvpn/transport.key"));
    assert!(!script.contains("--ipv6-tunnel-enabled true"));
    assert!(!script.contains("ip -6 address replace"));
    assert!(!script.contains("table ip6 sirinvpn_nat6 {"));
    assert!(script.contains("IPV6_ENABLED=0"));
    assert!(!script.contains("net/ipv6/conf/eth0/accept_ra=2"));
    assert!(script.contains("ReadWritePaths=/etc/sirinvpn/authorization"));
    assert!(script.contains(r#"{"schema_version":1,"external_interface":"eth0","ssh_port":22}"#));
    assert!(script.contains("chown root:sirinvpn /etc/sirinvpn/operational.json"));
    assert!(script.contains("chmod 0640 /etc/sirinvpn/operational.json"));
    assert!(script.contains("CapabilityBoundingSet=CAP_NET_ADMIN"));
    assert!(script.contains("AmbientCapabilities=CAP_NET_ADMIN"));
    assert!(!script.contains("ReadWritePaths=/etc/sirinvpn\n"));
    assert!(script.contains("systemctl disable --now sirinvpn-doh"));
    assert!(script.contains("rm -f /etc/systemd/system/sirinvpn-doh.service"));
    assert!(!script.contains("Description=SirinVPN DNS-over-HTTPS upstream proxy"));
    assert!(!script.contains(&format!("loopback port {DOH_PROXY_PORT}")));
    assert!(
        std::process::Command::new("/bin/sh")
            .arg("-n")
            .arg("-c")
            .arg(&script)
            .status()
            .unwrap()
            .success(),
        "generated installer script must be valid POSIX shell"
    );

    let server_identity = LocalIdentity::generate("Server").unwrap();
    let mut bootstrap = BootstrapOutput {
        endpoint_transition: None,
        wireguard_public_key: server_identity.public.wireguard_public_key,
        management_certificate_pem: server_identity.public.management_certificate_pem,
        server_tunnel_address: SERVER_TUNNEL_ADDRESS.parse().unwrap(),
        wireguard_port: 51_820,
        management_port: DEFAULT_MANAGEMENT_PORT,
        dns_upstream: DnsUpstream::Recursive,
        private_dns_records: Vec::new(),
        ipv6_tunnel_enabled: false,
        obfuscated_udp: Some(ObfuscatedUdpEndpoint {
            port: DEFAULT_OBFUSCATED_UDP_PORT,
            server_public_key: STANDARD.encode([7_u8; 32]),
        }),
        tcp_fallback: Some(TcpFallbackEndpoint {
            port: DEFAULT_TCP_FALLBACK_PORT,
            server_public_key: STANDARD.encode([7_u8; 32]),
        }),
        tls_like: Some(TlsLikeEndpoint {
            port: DEFAULT_TLS_LIKE_PORT,
            server_public_key: STANDARD.encode([7_u8; 32]),
            certificate_sha256: STANDARD.encode([8_u8; 32]),
            https: None,
        }),
    };
    let verification =
        install_verification_command("artifact-digest", &bootstrap, request.server_id, &discovery);
    assert!(verification.contains("attempt=0"));
    assert!(verification.contains("[ \"$attempt\" -lt 15 ]"));
    assert!(verification.contains("validate-state"));
    assert!(verification.contains("sha256sum /usr/local/lib/sirinvpn/sirinvpn-server"));
    assert!(verification.contains("stat -c '%a:%U:%G'"));
    assert!(verification.contains("authorization-required"));
    assert!(verification.contains("nft list table inet sirinvpn_filter"));
    assert!(verification.contains("nft list set inet sirinvpn_filter peer_communication4"));
    assert!(verification.contains("nft list set inet sirinvpn_filter peer_communication6"));
    assert!(verification.contains("nft list chain inet sirinvpn_filter port_forward"));
    assert!(verification.contains("nft list chain ip sirinvpn_nat port_forward_prerouting"));
    assert!(verification.contains("operational.json"));
    assert!(verification.contains("isolate-runtime"));
    assert!(verification.contains("nft list table ip sirinvpn_nat"));
    assert!(verification.contains("! nft list table ip6 sirinvpn_nat6"));
    assert!(verification.contains("10.77.0.1:53"));
    assert!(verification.contains("[ ! -e /etc/systemd/system/sirinvpn-doh.service ]"));
    assert!(
        std::process::Command::new("/bin/sh")
            .arg("-n")
            .arg("-c")
            .arg(verification)
            .status()
            .unwrap()
            .success(),
        "generated install verification must be valid POSIX shell"
    );

    let mut dual_stack_discovery = discovery.clone();
    dual_stack_discovery.ipv6_available = true;
    dual_stack_discovery.ipv6_default_interface = Some("ens6".to_owned());
    let dual_stack_script = install_script(
        &request,
        &dual_stack_discovery,
        "/tmp/server",
        "/tmp/owner",
        "dual-stack",
        script_transaction("10.77.0.2", true, false),
    );
    let server_ipv6 = ipv6_tunnel_address(request.server_id, Ipv4Addr::new(10, 77, 0, 1)).unwrap();
    let owner_ipv6 = ipv6_tunnel_address(request.server_id, Ipv4Addr::new(10, 77, 0, 2)).unwrap();
    let ipv6_cidr = ipv6_tunnel_cidr(request.server_id);
    assert!(dual_stack_script.contains("--ipv6-tunnel-enabled true"));
    assert!(dual_stack_script.contains(&format!(
        "ip -6 address replace {server_ipv6}/64 dev sirinvpn0"
    )));
    assert!(dual_stack_script.contains(&format!("allowed-ips 10.77.0.2/32,{owner_ipv6}/128")));
    assert!(dual_stack_script.contains("table ip6 sirinvpn_nat6 {"));
    assert!(dual_stack_script.contains(&format!(
        "ip6 saddr {ipv6_cidr} oifname \"ens6\" masquerade"
    )));
    assert!(dual_stack_script.contains(&format!("interface: {server_ipv6}")));
    assert!(dual_stack_script.contains("net/ipv6/conf/ens6/accept_ra=2"));
    assert!(dual_stack_script.contains("net.ipv6.conf.all.forwarding=1"));
    assert!(dual_stack_script.contains("--comment sirinvpn-forward6-out"));
    assert!(dual_stack_script.contains("$BACKUP_DIR/ipv6_accept_ra"));
    assert!(
        std::process::Command::new("/bin/sh")
            .arg("-n")
            .arg("-c")
            .arg(&dual_stack_script)
            .status()
            .unwrap()
            .success(),
        "generated dual-stack installer script must be valid POSIX shell"
    );

    bootstrap.ipv6_tunnel_enabled = true;
    let dual_stack_verification = install_verification_command(
        "artifact-digest",
        &bootstrap,
        request.server_id,
        &dual_stack_discovery,
    );
    let retry_end = dual_stack_verification.find("sleep 1\ndone").unwrap();
    let ipv6_check = dual_stack_verification
        .find(&format!("inet6 {server_ipv6}/64"))
        .unwrap();
    assert!(retry_end < ipv6_check);
    assert!(dual_stack_verification.contains("nft list table ip6 sirinvpn_nat6"));
    assert!(dual_stack_verification.contains(&format!("{owner_ipv6}/128")));
    assert!(
        std::process::Command::new("/bin/sh")
            .arg("-n")
            .arg("-c")
            .arg(&dual_stack_verification)
            .status()
            .unwrap()
            .success(),
        "generated dual-stack verification must be valid POSIX shell"
    );

    let mut replacement_request = request;
    replacement_request.replace_existing_installation = true;
    let replacement_script = install_script(
        &replacement_request,
        &discovery,
        "/tmp/server",
        "/tmp/owner",
        "replacement",
        script_transaction("10.77.0.2", discovery.ipv6_available, false),
    );
    let backup_position = replacement_script.find("tar -C / -cpf").unwrap();
    let guard_position = replacement_script
        .find(
            r#"systemctl enable --now "$ROLLBACK_SERVICE-boot.service" "$ROLLBACK_SERVICE.timer""#,
        )
        .unwrap();
    let replacement_position = replacement_script
        .find("Explicit SSH-authorized SirinVPN identity replacement")
        .unwrap();
    let initialize_position = replacement_script
        .find("/usr/local/lib/sirinvpn/sirinvpn-server init")
        .unwrap();
    assert!(guard_position < backup_position);
    assert!(guard_position < replacement_position);
    assert!(replacement_position < initialize_position);
    assert!(replacement_script.contains(
        "if systemctl cat \"$unit.service\" >/dev/null 2>&1; then\n    systemctl stop \"$unit.service\""
    ));
    assert!(replacement_script.contains(
        "rm -f -- /etc/sirinvpn/server.json /etc/sirinvpn/management.crt /etc/sirinvpn/management.key /etc/sirinvpn/wireguard.key /etc/sirinvpn/transport.key /etc/sirinvpn/https.key /etc/sirinvpn/authorization-required"
    ));
    assert!(replacement_script.contains("rm -rf -- /etc/sirinvpn/authorization"));
    assert!(
        std::process::Command::new("/bin/sh")
            .arg("-n")
            .arg("-c")
            .arg(&replacement_script)
            .status()
            .unwrap()
            .success(),
        "generated replacement script must be valid POSIX shell"
    );
}

#[test]
fn existing_owner_must_match_before_an_idempotent_install() {
    let certificate = "-----BEGIN CERTIFICATE-----\nowner\n-----END CERTIFICATE-----\n";
    let configuration = serde_json::json!({
        "schema_version": 1,
        "owner_certificate_pem": certificate,
    })
    .to_string();
    assert!(configuration_owner_matches(&configuration, certificate));
    assert!(!configuration_owner_matches(
        &configuration,
        "different owner"
    ));
    assert!(!configuration_owner_matches("not json", certificate));
}
