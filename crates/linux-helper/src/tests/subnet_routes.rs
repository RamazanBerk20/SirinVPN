use super::*;
use serde_json::{Value, json};

fn routed(
    routing: TunnelRoutingPolicy,
    announced: &[&str],
    reachable: &[&str],
) -> TunnelConnectRequest {
    let mut request = request();
    request.schema_version = 7;
    request.policy = Some(ConnectionPolicy {
        kill_switch: true,
        automatic_reconnect: true,
        connect_on_startup: false,
    });
    request.routing = routing;
    request.subnet_routes = sirinvpn_protocol::DeviceSubnetRoutes {
        announced: announced.iter().map(|route| route.to_string()).collect(),
        reachable: reachable.iter().map(|route| route.to_string()).collect(),
    };
    request
}

fn rules(objects: &[Value], chain: &str) -> Vec<String> {
    objects
        .iter()
        .filter_map(|object| object.get("rule"))
        .filter(|rule| rule["chain"] == chain)
        .map(|rule| rule["expr"].to_string())
        .collect()
}

fn position(rules: &[String], needle: &str) -> usize {
    rules
        .iter()
        .position(|rule| rule.contains(needle))
        .unwrap_or_else(|| panic!("{needle} not in {rules:#?}"))
}

#[test]
fn subnet_routes_need_a_policy_routed_mode_and_valid_distinct_ranges() {
    let full = TunnelRoutingPolicy::full_tunnel(false);
    assert!(
        validate_request(&routed(
            full.clone(),
            &["192.168.1.0/24"],
            &["10.20.0.0/20"]
        ))
        .is_ok()
    );
    let selected =
        TunnelRoutingPolicy::selected_routes(["198.51.100.0/24".to_owned()], true).unwrap();
    assert!(validate_request(&routed(selected, &[], &["192.168.1.0/24"])).is_ok());

    let mut legacy = routed(full.clone(), &["192.168.1.0/24"], &[]);
    legacy.schema_version = 6;
    legacy.policy = None;
    assert!(validate_request(&legacy).is_err());
    let mut applications = routed(full.clone(), &[], &["192.168.1.0/24"]);
    applications.schema_version = 11;
    applications.routing = TunnelRoutingPolicy::selected_applications(false);
    assert!(validate_request(&applications).is_err());
    for (announced, reachable) in [
        (&["192.168.1.0/24"][..], &["192.168.1.0/25"][..]),
        (&["192.168.1.1/24"], &[]),
        (&[], &["10.77.0.0/24"]),
        (&[], &["0.0.0.0/0"]),
        (&[], &["8.8.8.0/24"]),
    ] {
        assert!(
            validate_request(&routed(full.clone(), announced, reachable)).is_err(),
            "{announced:?} {reachable:?}"
        );
    }
}

#[test]
fn routers_keep_their_lan_and_accept_tunnel_traffic_for_it() {
    let request = routed(
        TunnelRoutingPolicy::full_tunnel(false),
        &["192.168.1.0/24"],
        &[],
    );
    let objects = enforcement::guard_objects(&request, "203.0.113.8".parse().unwrap());
    let output = rules(&objects, "output");
    let lan = json!({"prefix": {"addr": "192.168.1.0", "len": 24}}).to_string();
    // DNS stays protected before the router's own LAN is allowed.
    assert!(position(&output, "\"right\":53}") < position(&output, &lan));
    assert!(output[position(&output, &lan)].contains("accept"));
    let forward = rules(&objects, "forward");
    let accept = position(&forward, &lan);
    assert!(forward[accept].contains("iifname") && forward[accept].contains("accept"));
    assert!(accept < forward.len() - 1);
    assert_eq!(forward.last().unwrap(), "[{\"drop\":null}]");

    let firewall = client_firewall(&request);
    assert!(firewall.contains(concat!(
        "  chain subnet_nat {\n",
        "    type nat hook postrouting priority srcnat; policy accept;\n",
        "    iifname \"sirinvpn0\" ip daddr { 192.168.1.0/24 } masquerade\n",
        "  }\n}\n"
    )));
    assert!(
        !client_firewall(&routed(
            TunnelRoutingPolicy::full_tunnel(false),
            &[],
            &["192.168.1.0/24"]
        ))
        .contains("nat")
    );
    assert_eq!(
        subnet_route_rules(&request),
        [("192.168.1.0/24", false, "main")]
    );
    assert_eq!(wireguard_allowed_ips(&request), "0.0.0.0/0");

    // A selected-routes router also accepts and answers the tunnel addresses it forwards for.
    let selected =
        TunnelRoutingPolicy::selected_routes(["198.51.100.0/24".to_owned()], false).unwrap();
    let request = routed(selected, &["192.168.1.0/24"], &[]);
    assert_eq!(
        wireguard_allowed_ips(&request),
        "10.77.0.0/24,10.77.0.1/32,198.51.100.0/24"
    );
    assert_eq!(
        route_table_destinations(&request, "-4"),
        ["10.77.0.0/24", "10.77.0.1/32", "198.51.100.0/24"]
    );
}

#[test]
fn reachable_routes_use_the_tunnel_even_with_local_network_access() {
    let request = routed(
        TunnelRoutingPolicy::full_tunnel(true),
        &[],
        &["192.168.1.0/24"],
    );
    let objects = enforcement::guard_objects(&request, "203.0.113.8".parse().unwrap());
    let route = json!({"prefix": {"addr": "192.168.1.0", "len": 24}}).to_string();
    let lan = json!({"prefix": {"addr": "192.168.0.0", "len": 16}}).to_string();
    for chain in ["output", "forward"] {
        let rules = rules(&objects, chain);
        let drop = position(&rules, &route);
        assert!(rules[drop].contains("drop"), "{chain}");
        assert!(drop < position(&rules, &lan), "{chain}");
    }
    // The helper's marked sockets (resolvers, the carrier) keep the physical link first.
    assert_eq!(
        subnet_route_rules(&request),
        [
            ("192.168.1.0/24", true, "main"),
            ("192.168.1.0/24", false, "51820")
        ]
    );

    let selected = TunnelRoutingPolicy::selected_routes(
        ["192.168.1.0/24".to_owned(), "198.51.100.0/24".to_owned()],
        false,
    )
    .unwrap();
    let request = routed(selected, &[], &["192.168.1.0/24", "10.20.0.0/20"]);
    assert_eq!(
        wireguard_allowed_ips(&request),
        "10.20.0.0/20,10.77.0.1/32,192.168.1.0/24,198.51.100.0/24"
    );
    assert_eq!(
        route_table_destinations(&request, "-4"),
        [
            "10.20.0.0/20",
            "10.77.0.1/32",
            "192.168.1.0/24",
            "198.51.100.0/24"
        ]
    );
}

#[test]
fn subnet_rules_are_applied_ahead_of_local_network_rules() {
    let directory = tempfile::tempdir().unwrap();
    let runner = RecordingRunner::default();
    let helper = LinuxNetworkHelper::new(runner.clone(), directory.path().to_path_buf());
    let request = routed(
        TunnelRoutingPolicy::full_tunnel(true),
        &["192.168.1.0/24"],
        &["10.20.0.0/20"],
    );
    helper
        .apply(&request, "203.0.113.8".parse().unwrap(), false)
        .unwrap();
    let commands = runner.commands.lock().unwrap().clone();
    let index = |arguments: &[&str]| {
        commands
            .iter()
            .position(|(program, recorded, _)| program == "ip" && recorded == arguments)
            .unwrap_or_else(|| panic!("{arguments:?}"))
    };
    index(&[
        "-4",
        "rule",
        "add",
        "to",
        "192.168.1.0/24",
        "table",
        "main",
        "priority",
        "9989",
    ]);
    let marked = index(&[
        "-4",
        "rule",
        "add",
        "to",
        "10.20.0.0/20",
        "fwmark",
        "51820",
        "table",
        "main",
        "priority",
        "9989",
    ]);
    // Rules at one priority match in insertion order.
    assert!(
        marked
            < index(&[
                "-4",
                "rule",
                "add",
                "to",
                "10.20.0.0/20",
                "table",
                "51820",
                "priority",
                "9989",
            ])
    );
    index(&[
        "-4",
        "rule",
        "add",
        "to",
        "192.168.0.0/16",
        "table",
        "main",
        "priority",
        "9993",
    ]);
    // A lower number wins: subnet rules come before DNS and local-network rules.
    assert!(
        SUBNET_RULE_PRIORITY.parse::<u16>().unwrap() < DNS_RULE_PRIORITY.parse::<u16>().unwrap()
    );
}

#[test]
#[ignore = "requires a disposable network namespace; use tests/network/run-policy-kernel.sh"]
fn kernel_subnet_router_forwards_its_lan_and_keeps_reaching_it() {
    assert_eq!(
        std::env::var("SIRINVPN_POLICY_ISOLATED").as_deref(),
        Ok("1")
    );
    assert!(Path::new("/.dockerenv").exists());
    let dir = tempfile::tempdir().unwrap();
    let prepared = Command::new("python3")
        .args(["tests/network/subnet_router.py", "prepare"])
        .arg(dir.path())
        .output()
        .unwrap();
    assert!(prepared.status.success(), "lab preparation failed");
    let keys: Value = serde_json::from_slice(&prepared.stdout).unwrap();
    // 10.20.0.0/20 is another device's LAN that this router's own uplink also routes.
    let mut request = routed(
        TunnelRoutingPolicy::full_tunnel(false),
        &["192.168.1.0/24"],
        &["10.20.0.0/20"],
    );
    request.endpoint_host = "198.51.100.1".into();
    request.server_public_key = keys["vps_public_key"].as_str().unwrap().into();
    request.private_key = keys["router_private_key"].as_str().unwrap().into();
    let probe = |source: &str, destination: &str, open: bool| {
        let status = Command::new("python3")
            .args([
                "tests/network/subnet_router.py",
                "probe",
                source,
                destination,
            ])
            .arg(if open { "open" } else { "blocked" })
            .status()
            .unwrap();
        assert!(
            status.success(),
            "{source} -> {destination} should be open: {open}"
        );
    };
    let helper =
        LinuxNetworkHelper::new(super::session_kernel::SessionRunner, dir.path().join("run"));
    helper.connect(&request).unwrap();
    assert!(helper.guard_is_verified(&request, "198.51.100.1".parse().unwrap()));
    assert!(helper.tunnel_configuration_exists(&request));
    probe("router", "10.77.0.1", true);
    // Under the full-tunnel kill switch the router still reaches its own LAN directly.
    probe("router", "192.168.1.10", true);
    probe("consumer", "192.168.1.10", true);
    let route = |arguments: &[&str]| {
        String::from_utf8(SystemRunner.output("ip", arguments).unwrap()).unwrap()
    };
    assert!(route(&["-4", "route", "get", "10.20.0.1"]).contains("dev sirinvpn0"));
    // The helper's own marked sockets (resolvers, the carrier) stay on the physical link.
    for destination in ["10.20.0.1", "198.51.100.1"] {
        let marked = route(&["-4", "route", "get", destination, "mark", "51820"]);
        assert!(marked.contains("dev uplink0"), "{destination}: {marked}");
    }
    println!(
        "subnet router: tunnel, own LAN and forwarded peer traffic work under the kill switch"
    );

    helper.disconnect_session(request.server_id).unwrap();
    probe("consumer", "192.168.1.10", false);
    probe("router", "192.168.1.10", true);
    let rules = SystemRunner
        .output(
            "ip",
            &["-4", "rule", "show", "priority", SUBNET_RULE_PRIORITY],
        )
        .unwrap();
    assert!(rules.iter().all(u8::is_ascii_whitespace));
    assert!(!SystemRunner.succeeds("nft", &["list", "table", "inet", "sirinvpn_client"]));
    println!("subnet router: disconnect removes forwarding, NAT and routing rules");
}
