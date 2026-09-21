use super::*;

fn ip(arguments: &[&str]) {
    let output = Command::new("ip").args(arguments).output().unwrap();
    assert!(
        output.status.success(),
        "ip {arguments:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn tunnel_link() {
    ip(&[
        "link",
        "add",
        INTERFACE_NAME,
        "type",
        "veth",
        "peer",
        "name",
        "vpn-peer",
        "netns",
        "vpn-proof",
    ]);
    ip(&["address", "add", "10.77.0.2/24", "dev", INTERFACE_NAME]);
    ip(&[
        "-6",
        "address",
        "add",
        "fd77::2/64",
        "dev",
        INTERFACE_NAME,
        "nodad",
    ]);
    ip(&["link", "set", INTERFACE_NAME, "up"]);
    for (family, address) in [
        ("-4", "10.77.0.1/24"),
        ("-4", "198.51.100.9/32"),
        ("-6", "fd77::1/64"),
        ("-6", "2001:db8:1::9/128"),
    ] {
        let mut args = vec![
            "-n",
            "vpn-proof",
            family,
            "address",
            "add",
            address,
            "dev",
            "vpn-peer",
        ];
        if family == "-6" {
            args.push("nodad");
        }
        ip(&args);
    }
    ip(&["-n", "vpn-proof", "link", "set", "vpn-peer", "up"]);
}

fn configure(helper: &LinuxNetworkHelper, request: &TunnelConnectRequest) {
    helper.apply_policy_routes(request, "-4").unwrap();
    helper.apply_policy_routes(request, "-6").unwrap();
    helper.apply_lan_exceptions(request).unwrap();
    if let Err(error) = helper.apply_application_routing(request) {
        let actual = SystemRunner
            .output("nft", &["-j", "list", "table", "inet", firewall::TABLE])
            .unwrap_or_default();
        eprintln!("Actual guard: {}", String::from_utf8_lossy(&actual));
        eprintln!(
            "Expected guard: {}",
            serde_json::to_string(&firewall::objects(request)).unwrap()
        );
        panic!("application routing: {error}");
    }
}

fn proof_script() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/network/application_routing.py")
}

fn probe(phase: &str) {
    let status = Command::new("python3")
        .arg(proof_script())
        .args(["probe", phase])
        .status()
        .unwrap();
    if !status.success() {
        for args in [
            vec!["-6", "route", "show", "table", "all"],
            vec!["-6", "neigh", "show"],
            vec!["-n", NAMESPACE, "-6", "neigh", "show"],
            vec!["-n", "vpn-proof", "-6", "neigh", "show"],
        ] {
            eprintln!(
                "ip {args:?}: {}",
                String::from_utf8_lossy(&SystemRunner.output("ip", &args).unwrap_or_default())
            );
        }
    }
    assert!(status.success(), "application packet phase {phase}");
}

#[test]
#[ignore = "requires a disposable, capped network-namespace container"]
fn kernel_application_packet_dns_privilege_and_disconnect_matrix() {
    assert_eq!(
        std::env::var("SIRINVPN_POLICY_ISOLATED").as_deref(),
        Ok("1")
    );
    assert!(Path::new("/.dockerenv").exists());
    require_root().unwrap();
    let links: Vec<serde_json::Value> =
        serde_json::from_slice(&SystemRunner.output("ip", &["-j", "link", "show"]).unwrap())
            .unwrap();
    assert_eq!(links.len(), 1, "test requires Docker --network none");
    assert_eq!(links[0]["ifname"], "lo");
    let setup = Command::new("python3")
        .arg(proof_script())
        .arg("setup")
        .status()
        .unwrap();
    assert!(setup.success());
    tunnel_link();
    assert!(
        Command::new("python3")
            .arg(proof_script())
            .arg("start")
            .status()
            .unwrap()
            .success()
    );
    let helper = LinuxNetworkHelper::system();
    let operation = helper.lock_operations().unwrap();
    let mut request = application_request();
    request.client_ipv6_address = Some("fd77::2".parse().unwrap());
    let mut state = RuntimeState::for_policy(&request);
    state.has_connected = true;
    state.reconnecting = false;
    helper.write_state(&state).unwrap();
    configure(&helper, &request);
    for family in ["-4", "-6"] {
        let output = SystemRunner
            .output(
                "ip",
                &[
                    family,
                    "-j",
                    "rule",
                    "show",
                    "priority",
                    FALLBACK_BLOCK_PRIORITY,
                ],
            )
            .unwrap();
        assert!(
            helper.application_fallback_rule_exists(family),
            "fallback rule: {}",
            String::from_utf8_lossy(&output)
        );
    }
    helper.prepare_application_network(&request, 1000).unwrap();
    assert!(helper.application_configuration_exists(&request));
    fs::write("/tmp/application-server-id", request.server_id.to_string()).unwrap();
    drop(operation);
    probe("active");
    // A sudden loss of the tunnel must not fall back even with the optional
    // host kill switch disabled. No helper cleanup occurs before this probe.
    ip(&["link", "delete", INTERFACE_NAME]);
    probe("missing-tunnel");
    helper.cleanup_tunnel_owned().unwrap();
    tunnel_link();
    configure(&helper, &request);
    assert!(helper.application_configuration_exists(&request));
    probe("reconnected");
    // A rotated peer may receive new tunnel addresses while the existing app
    // retains its namespace. The new SNAT addresses must be visible at the exit.
    ip(&["address", "add", "10.77.0.3/24", "dev", INTERFACE_NAME]);
    ip(&[
        "-6",
        "address",
        "add",
        "fd77::3/64",
        "dev",
        INTERFACE_NAME,
        "nodad",
    ]);
    request.client_address = "10.77.0.3".parse().unwrap();
    request.client_ipv6_address = Some("fd77::3".parse().unwrap());
    helper.apply_application_routing(&request).unwrap();
    assert!(helper.application_configuration_exists(&request));
    probe("rotated");
    ip(&["-4", "rule", "delete", "priority", DNS_BLOCK_PRIORITY]);
    assert!(!helper.application_configuration_exists(&request));
    ip(&[
        "-4",
        "rule",
        "add",
        "iif",
        HOST_LINK,
        "to",
        "10.77.0.1/32",
        "prohibit",
        "priority",
        DNS_BLOCK_PRIORITY,
    ]);
    assert!(helper.application_configuration_exists(&request));
    helper.cleanup_tunnel_owned().unwrap();
    helper.destroy_applications().unwrap();
    probe("disconnected");

    // LAN bypass remains explicit and keeps ordinary DNS ports inside the VPN.
    tunnel_link();
    request.client_address = "10.77.0.2".parse().unwrap();
    request.client_ipv6_address = Some("fd77::2".parse().unwrap());
    request.routing.allow_lan = true;
    state.routing.allow_lan = true;
    helper.write_state(&state).unwrap();
    configure(&helper, &request);
    if let Err(error) = helper.prepare_application_network(&request, 1000) {
        for family in ["-4", "-6"] {
            eprintln!(
                "{family} rules: {}",
                String::from_utf8_lossy(
                    &SystemRunner.output("ip", &[family, "-j", "rule"]).unwrap()
                )
            );
        }
        panic!("LAN application setup: {error}");
    }
    probe("lan");
    let metadata = fs::read(helper.application_path()).unwrap();
    fs::remove_file(helper.application_path()).unwrap();
    assert!(helper.destroy_applications().is_err());
    assert!(helper.application_guard_is_verified(&request));
    write_owned_file(&helper.application_path(), &metadata, 0o600).unwrap();
    // An IPv4-only profile blocks IPv6 explicitly, including during a live
    // policy replacement. Ordinary host IPv6 remains on its original route.
    request.client_ipv6_address = None;
    helper.apply_application_routing(&request).unwrap();
    assert!(helper.application_configuration_exists(&request));
    probe("ipv4-only");
    helper.cleanup_tunnel_owned().unwrap();
    helper.destroy_applications().unwrap();
}
