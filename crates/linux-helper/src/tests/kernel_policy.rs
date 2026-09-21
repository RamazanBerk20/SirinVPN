//! Real nftables/IPv4/IPv6/DNS tests run only in the documented isolated container.
use super::*;

#[test]
#[ignore = "requires a disposable network namespace; use tests/network/run-policy-kernel.sh"]
fn kernel_guard_packet_matrix_and_atomic_replacement() {
    assert_eq!(
        std::env::var("SIRINVPN_POLICY_ISOLATED").as_deref(),
        Ok("1")
    );
    assert!(Path::new("/.dockerenv").exists());
    let interfaces: Vec<serde_json::Value> =
        serde_json::from_slice(&SystemRunner.output("ip", &["-j", "link", "show"]).unwrap())
            .unwrap();
    assert!(
        interfaces.len() == 1 && interfaces[0]["ifname"] == "lo",
        "Start with --network none; refuse preexisting interfaces"
    );
    let dir = tempfile::tempdir().unwrap();
    let helper = LinuxNetworkHelper::new(SystemRunner, dir.path().to_owned());
    let run_probe = |mode: &str| {
        let status = Command::new("python3")
            .args(["tests/network/policy_packets.py", mode])
            .status()
            .unwrap();
        assert!(status.success(), "packet probe: {mode}");
    };
    run_probe("prepare");
    run_probe("off");
    let unrelated = b"table inet unrelated_test {\n chain keep {\n type filter hook output priority -50; policy accept;\n }\n}\n";
    SystemRunner
        .run("nft", &["-f", "-"], Some(unrelated))
        .unwrap();
    let unrelated_before = SystemRunner
        .output("nft", &["-j", "list", "table", "inet", "unrelated_test"])
        .unwrap();
    let mut request = request();
    request.schema_version = 7;
    request.policy = Some(ConnectionPolicy {
        kill_switch: true,
        automatic_reconnect: false,
        connect_on_startup: false,
    });
    let endpoint = "203.0.113.8".parse().unwrap();
    for mode in ["full", "lan", "selected", "tcp"] {
        request.routing = match mode {
            "lan" => TunnelRoutingPolicy::full_tunnel(true),
            "selected" => TunnelRoutingPolicy::selected_routes(
                ["203.0.113.8/32".into(), "2001:db8::8/128".into()],
                false,
            )
            .unwrap(),
            _ => TunnelRoutingPolicy::default(),
        };
        if mode == "tcp" {
            request.transport = TransportKind::TcpFallback;
            request.endpoint_port = 443;
        }
        if let Err(error) = helper.apply_policy_guard(&request, endpoint) {
            eprintln!(
                "expected: {}",
                serde_json::to_string(&crate::enforcement::guard_objects(&request, endpoint))
                    .unwrap()
            );
            eprintln!(
                "observed: {}",
                String::from_utf8_lossy(
                    &SystemRunner
                        .output("nft", &["-j", "list", "table", "inet", "sirinvpn_guard"])
                        .unwrap_or_default()
                )
            );
            panic!("{error}");
        }
        run_probe(mode);
    }
    // A rejected replacement transaction must keep the previous protection intact.
    let before = SystemRunner
        .output("nft", &["-j", "list", "table", "inet", "sirinvpn_guard"])
        .unwrap();
    assert!(
        SystemRunner
            .run(
                "nft",
                &["-f", "-"],
                Some(b"delete table inet sirinvpn_guard\nadd rule inet absent absent accept\n")
            )
            .is_err()
    );
    assert_eq!(
        before,
        SystemRunner
            .output("nft", &["-j", "list", "table", "inet", "sirinvpn_guard"])
            .unwrap()
    );
    run_probe("tcp");
    // Repeated atomic transport changes retain the block and unrelated tables.
    let stopped = Arc::new(AtomicBool::new(false));
    let probes = [
        ("203.0.113.7:0", "203.0.113.8:3333"),
        ("[2001:db8::7]:0", "[2001:db8::8]:3333"),
    ]
    .map(|(source, target)| {
        let stopped = stopped.clone();
        thread::spawn(move || {
            let socket = std::net::UdpSocket::bind(source).unwrap();
            socket.connect(target).unwrap();
            socket
                .set_read_timeout(Some(Duration::from_millis(2)))
                .unwrap();
            let mut attempts = 0_u64;
            let mut leaks = 0_u64;
            while !stopped.load(Ordering::SeqCst) {
                attempts += 1;
                if socket.send(b"gap-probe").is_ok() && socket.recv(&mut [0_u8; 64]).is_ok() {
                    leaks += 1;
                }
            }
            (attempts, leaks)
        })
    });
    for n in 0..30 {
        request.transport = if n % 2 == 0 {
            TransportKind::DirectUdp
        } else {
            TransportKind::TcpFallback
        };
        request.endpoint_port = if n % 2 == 0 { 51820 } else { 443 };
        helper.apply_policy_guard(&request, endpoint).unwrap();
    }
    stopped.store(true, Ordering::SeqCst);
    for probe in probes {
        let (attempts, leaks) = probe.join().unwrap();
        assert!(attempts > 30);
        assert_eq!(leaks, 0);
        println!("atomic replacement: {attempts} real packet attempts, {leaks} observed leaks");
    }
    assert_eq!(
        unrelated_before,
        SystemRunner
            .output("nft", &["-j", "list", "table", "inet", "unrelated_test"])
            .unwrap()
    );
    helper
        .write_state(&RuntimeState::for_policy(&request))
        .unwrap();
    helper.disconnect().unwrap();
    run_probe("off");
    assert_eq!(
        unrelated_before,
        SystemRunner
            .output("nft", &["-j", "list", "table", "inet", "unrelated_test"])
            .unwrap()
    );
    // Lose the actual interface after an acknowledged guard observation, before
    // the supervisor's next tick. Both IP families and DNS must stay blocked.
    for kill in [false, true] {
        for reconnect in [false, true] {
            request.routing = TunnelRoutingPolicy::default();
            request.transport = TransportKind::DirectUdp;
            request.endpoint_port = 51820;
            request.policy = Some(ConnectionPolicy {
                kill_switch: kill,
                automatic_reconnect: reconnect,
                connect_on_startup: false,
            });
            SystemRunner
                .run(
                    "ip",
                    &[
                        "link",
                        "add",
                        INTERFACE_NAME,
                        "type",
                        "veth",
                        "peer",
                        "name",
                        "failure-peer",
                    ],
                    None,
                )
                .unwrap();
            if kill {
                helper.apply_policy_guard(&request, endpoint).unwrap();
            }
            let mut state = RuntimeState::for_policy(&request);
            state.has_connected = true;
            state.reconnecting = false;
            helper.observe_policy(&mut state, &request, endpoint);
            helper.write_state(&state).unwrap();
            SystemRunner
                .run("ip", &["link", "delete", INTERFACE_NAME], None)
                .unwrap();
            let missing = helper.status().unwrap();
            assert_eq!(
                missing.kill_switch_state,
                Some(if kill {
                    KillSwitchState::Blocking
                } else {
                    KillSwitchState::Off
                })
            );
            assert_eq!(missing.ipv6_blocked, kill);
            assert_eq!(missing.auto_reconnect_enabled, reconnect);
            run_probe(if kill { "full" } else { "off" });
            // Simulate an unavailable monitor without changing kernel policy.
            state.observed_at_boot_seconds = None;
            helper.write_state(&state).unwrap();
            assert_eq!(
                helper.status().unwrap().kill_switch_state,
                Some(KillSwitchState::Unknown)
            );
            helper.disconnect().unwrap();
        }
    }
    // Restore boot protection from saved root intent with no runtime state.
    super::endpoint_kernel::check_endpoints();
    super::session_kernel::check_sessions();
    request.policy.as_mut().unwrap().kill_switch = true;
    request.policy.as_mut().unwrap().connect_on_startup = true;
    helper
        .write_persistent(&PersistentConnection {
            resolved_endpoints: Vec::new(),
            schema_version: 2,
            request: request.clone(),
            endpoint,
            obfuscated_udp: None,
            tcp_fallback: None,
            extended_routing: None,
        })
        .unwrap();
    helper.restore_kill_switch().unwrap();
    run_probe("full");
    // This fixture does not run systemd; delete only its disposable intent before
    // exercising explicit Disconnect, which verifies and removes the guard.
    fs::remove_file(helper.persistent_path()).unwrap();
    helper
        .write_state(&RuntimeState::for_policy(&request))
        .unwrap();
    helper.disconnect().unwrap();
    run_probe("off");
    assert_eq!(
        unrelated_before,
        SystemRunner
            .output("nft", &["-j", "list", "table", "inet", "unrelated_test"])
            .unwrap()
    );
}
