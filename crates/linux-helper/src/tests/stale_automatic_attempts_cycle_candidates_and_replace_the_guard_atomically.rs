use super::*;

#[test]
fn stale_automatic_attempts_cycle_candidates_and_replace_the_guard_atomically() {
    let directory = tempfile::tempdir().unwrap();
    let runner = RecordingRunner::default();
    let helper = LinuxNetworkHelper::new(runner.clone(), directory.path().to_path_buf());
    helper.connect(&persistent_automatic_request()).unwrap();
    runner.commands.lock().unwrap().clear();

    let age_attempt = || {
        let mut state = helper.read_state().unwrap();
        state.applied_at_unix = now_unix().saturating_sub(HANDSHAKE_GRACE_SECONDS);
        helper.write_state(&state).unwrap();
    };
    let last_guard = || {
        runner
            .commands
            .lock()
            .unwrap()
            .iter()
            .rev()
            .find(|(program, arguments, input)| {
                program == "nft"
                    && arguments == &["-f", "-"]
                    && String::from_utf8_lossy(input).contains("sirinvpn_guard")
            })
            .map(|(_, _, input)| String::from_utf8_lossy(input).into_owned())
            .unwrap()
    };

    age_attempt();
    assert_eq!(
        helper.reconcile_persistent_once(true).unwrap(),
        ReconcileOutcome::AwaitingHandshake
    );
    assert_eq!(
        helper.read_state().unwrap().transport,
        TransportKind::ObfuscatedUdp
    );
    assert!(helper.read_state().unwrap().transport_fallback_enabled);
    let guard = last_guard();
    assert!(guard.starts_with("flush chain inet sirinvpn_guard output\n"));
    assert!(guard.contains("udp dport 443 accept"));

    helper.restore_kill_switch().unwrap();
    assert!(last_guard().contains("udp dport 443 accept"));

    age_attempt();
    helper.reconcile_persistent_once(true).unwrap();
    assert_eq!(
        helper.read_state().unwrap().transport,
        TransportKind::TcpFallback
    );
    assert!(last_guard().contains("tcp dport 443 accept"));

    age_attempt();
    helper.reconcile_persistent_once(true).unwrap();
    assert_eq!(
        helper.read_state().unwrap().transport,
        TransportKind::DirectUdp
    );
    assert!(last_guard().contains("udp dport 51820 accept"));
    assert!(!directory.path().join("transport.json").exists());
}

#[test]
fn automatic_failover_stops_when_owned_cleanup_is_uncertain() {
    let directory = tempfile::tempdir().unwrap();
    let runner = RecordingRunner {
        cleanup_residue: true,
        ..RecordingRunner::default()
    };
    let helper = LinuxNetworkHelper::new(runner.clone(), directory.path().to_path_buf());
    helper.connect(&persistent_automatic_request()).unwrap();
    runner.commands.lock().unwrap().clear();
    runner.apply_failed.store(true, Ordering::SeqCst);
    let mut state = helper.read_state().unwrap();
    state.applied_at_unix = now_unix().saturating_sub(HANDSHAKE_GRACE_SECONDS);
    helper.write_state(&state).unwrap();

    assert!(matches!(
        helper.reconcile_persistent_once(true),
        Err(HelperError::NetworkOperationFailed)
    ));
    assert_eq!(
        helper.read_state().unwrap().transport,
        TransportKind::DirectUdp
    );
    assert!(
        runner
            .commands
            .lock()
            .unwrap()
            .iter()
            .all(|(program, arguments, input)| {
                program != "nft"
                    || arguments != &["-f", "-"]
                    || !String::from_utf8_lossy(input).contains("sirinvpn_guard")
            })
    );
}

#[test]
fn persistent_obfuscated_state_keeps_a_fail_closed_legacy_reader_shape() {
    let directory = tempfile::tempdir().unwrap();
    let runner = RecordingRunner::default();
    let helper = LinuxNetworkHelper::new(runner, directory.path().to_path_buf());
    let mut request = persistent_automatic_request();
    request.reconnect_candidates.rotate_left(1);
    request.schema_version = 3;
    request.endpoint_port = 443;
    request.transport = TransportKind::ObfuscatedUdp;
    request.server_transport_public_key = Some(STANDARD.encode([9_u8; 32]));
    request.mtu = 1_320;

    helper.connect(&request).unwrap();
    let desired = directory.path().join("persistent/desired-connection.json");
    let bytes = fs::read(&desired).unwrap();
    let persisted: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(persisted["request"]["schema_version"], 2);
    assert!(persisted["request"].get("transport").is_none());
    assert!(
        persisted["request"]
            .get("server_transport_public_key")
            .is_none()
    );
    assert_eq!(
        persisted["obfuscated_udp"]["server_transport_public_key"],
        STANDARD.encode([9_u8; 32])
    );

    let legacy: LegacyPersistentConnectionV6 = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(legacy.schema_version, 1);
    assert_eq!(legacy.endpoint, Ipv4Addr::new(203, 0, 113, 8));
    assert_eq!(legacy.request.transport, TransportKind::DirectUdp);
    assert_eq!(legacy.request.endpoint_port, 443);
    assert!(legacy.request.server_transport_public_key.is_none());
    assert!(legacy.obfuscated_udp.is_some());
    assert!(legacy.tcp_fallback.is_none());

    let current = helper.read_persistent().unwrap();
    assert_eq!(current.request.transport, TransportKind::ObfuscatedUdp);
    assert_eq!(
        current.request.reconnect_candidates[0].transport,
        TransportKind::ObfuscatedUdp
    );
    assert_eq!(
        current.request.server_transport_public_key,
        request.server_transport_public_key
    );
}

#[test]
fn persistent_tcp_state_is_recoverable_now_and_fail_closed_for_legacy_helpers() {
    let directory = tempfile::tempdir().unwrap();
    let runner = RecordingRunner::default();
    let helper = LinuxNetworkHelper::new(runner, directory.path().to_path_buf());
    let mut request = persistent_automatic_request();
    request.reconnect_candidates.rotate_right(1);
    request.schema_version = 4;
    request.endpoint_port = 443;
    request.transport = TransportKind::TcpFallback;
    request.server_transport_public_key = Some(STANDARD.encode([10_u8; 32]));
    request.mtu = 1_280;

    helper.connect(&request).unwrap();
    let desired = directory.path().join("persistent/desired-connection.json");
    let bytes = fs::read(&desired).unwrap();
    let persisted: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(persisted["request"]["schema_version"], 2);
    assert!(persisted["request"].get("transport").is_none());
    assert!(
        persisted["request"]
            .get("server_transport_public_key")
            .is_none()
    );
    assert!(persisted.get("obfuscated_udp").is_none());
    assert_eq!(
        persisted["tcp_fallback"]["server_transport_public_key"],
        STANDARD.encode([10_u8; 32])
    );

    let legacy: LegacyPersistentConnectionV6 = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(legacy.schema_version, 1);
    assert_eq!(legacy.endpoint, Ipv4Addr::new(203, 0, 113, 8));
    assert_eq!(legacy.request.transport, TransportKind::DirectUdp);
    assert_eq!(legacy.request.endpoint_port, 443);
    assert!(legacy.request.server_transport_public_key.is_none());
    assert!(legacy.obfuscated_udp.is_none());
    assert!(legacy.tcp_fallback.is_some());

    let current = helper.read_persistent().unwrap();
    assert_eq!(current.request.transport, TransportKind::TcpFallback);
    assert_eq!(current.request.schema_version, 4);
    assert_eq!(
        current.request.reconnect_candidates[0].transport,
        TransportKind::TcpFallback
    );
    assert_eq!(
        current.request.server_transport_public_key,
        request.server_transport_public_key
    );
}

#[test]
fn persistent_apply_failure_keeps_the_guard_and_reconnect_intent() {
    let directory = tempfile::tempdir().unwrap();
    let runner = RecordingRunner {
        fail_apply: true,
        ..RecordingRunner::default()
    };
    let helper = LinuxNetworkHelper::new(runner.clone(), directory.path().to_path_buf());
    let mut request = request();
    request.persistent_protection = true;

    let status = helper.connect(&request).unwrap();

    assert_eq!(status.state, ConnectionState::Degraded);
    assert!(status.kill_switch_enabled);
    assert!(
        directory
            .path()
            .join("persistent/desired-connection.json")
            .exists()
    );
    let commands = runner.commands.lock().unwrap();
    assert!(commands.iter().any(|(program, arguments, stdin)| {
        program == "nft"
            && arguments == &["-f", "-"]
            && String::from_utf8_lossy(stdin).contains("policy drop")
    }));
    assert!(!commands.iter().any(|(program, arguments, _)| {
        program == "nft" && arguments == &["delete", "table", "inet", "sirinvpn_guard"]
    }));
}

#[test]
fn failed_supervisor_start_rolls_back_persistent_protection() {
    let directory = tempfile::tempdir().unwrap();
    let runner = RecordingRunner {
        fail_service_start: true,
        ..RecordingRunner::default()
    };
    let helper = LinuxNetworkHelper::new(runner, directory.path().to_path_buf());
    let mut request = request();
    request.persistent_protection = true;

    assert!(matches!(
        helper.connect(&request),
        Err(HelperError::PersistentProtectionUnavailable)
    ));
    assert!(!directory.path().join("client-state.json").exists());
    assert!(
        !directory
            .path()
            .join("persistent/desired-connection.json")
            .exists()
    );
}

#[test]
fn explicit_disconnect_removes_persistent_intent_and_disables_services() {
    let directory = tempfile::tempdir().unwrap();
    let runner = RecordingRunner::default();
    let helper = LinuxNetworkHelper::new(runner.clone(), directory.path().to_path_buf());
    let mut request = request();
    request.persistent_protection = true;
    helper.connect(&request).unwrap();

    let status = helper.disconnect().unwrap();

    assert_eq!(status, disconnected_status());
    assert!(!directory.path().join("client-state.json").exists());
    assert!(
        !directory
            .path()
            .join("persistent/desired-connection.json")
            .exists()
    );
    assert!(
        runner
            .commands
            .lock()
            .unwrap()
            .iter()
            .any(|(program, arguments, _)| {
                program == "systemctl"
                    && arguments == &["disable", KILL_SWITCH_UNIT, RECONNECT_UNIT]
            })
    );
}

#[test]
fn kill_switch_only_allows_recovery_paths() {
    let mut request = request();
    let firewall = kill_switch_firewall(&request, IpAddr::V4(Ipv4Addr::new(203, 0, 113, 8)), false);
    assert!(firewall.contains("policy drop"));
    assert!(firewall.contains("oifname \"lo\" accept"));
    assert!(firewall.contains(&format!("oifname \"{INTERFACE_NAME}\" accept")));
    assert!(firewall.contains("meta mark 0xca6c ip daddr 203.0.113.8 udp dport 51820 accept"));
    assert!(firewall.contains("udp sport 68 udp dport 67 accept"));
    assert!(!firewall.contains("dport 53"));

    request.endpoint_port = 443;
    request.transport = TransportKind::TcpFallback;
    let tcp_firewall =
        kill_switch_firewall(&request, IpAddr::V4(Ipv4Addr::new(203, 0, 113, 8)), false);
    assert!(tcp_firewall.contains("meta mark 0xca6c ip daddr 203.0.113.8 tcp dport 443 accept"));
    assert!(!tcp_firewall.contains("ip daddr 203.0.113.8 udp dport 443 accept"));
    request.transport = TransportKind::TlsLike;
    let tls_firewall =
        kill_switch_firewall(&request, IpAddr::V4(Ipv4Addr::new(203, 0, 113, 8)), false);
    assert!(tls_firewall.contains("meta mark 0xca6c ip daddr 203.0.113.8 tcp dport 443 accept"));

    request.endpoint_port = 51_820;
    request.transport = TransportKind::DirectUdp;
    let replacement =
        kill_switch_firewall(&request, IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)), true);
    assert!(replacement.starts_with("flush chain inet sirinvpn_guard output\n"));

    request.schema_version = 6;
    request.routing = TunnelRoutingPolicy::full_tunnel(true);
    let lan_firewall =
        kill_switch_firewall(&request, IpAddr::V4(Ipv4Addr::new(203, 0, 113, 8)), false);
    assert!(lan_firewall.contains("policy drop"));
    assert!(lan_firewall.contains("udp dport { 53, 853 } drop"));
    let dns_drop = lan_firewall.find("ip daddr 10.77.0.1 drop").unwrap();
    let lan_accept = lan_firewall.find("ip daddr 10.0.0.0/8 accept").unwrap();
    assert!(dns_drop < lan_accept);
}

#[test]
fn reconnect_units_restore_the_guard_before_networking_without_logs() {
    assert!(KILL_SWITCH_SERVICE.contains("Before=network-pre.target"));
    assert!(KILL_SWITCH_SERVICE.contains("WantedBy=network-pre.target"));
    assert!(RECONNECT_SERVICE.contains("After=sirinvpn-killswitch.service"));
    assert!(RECONNECT_SERVICE.contains("Restart=on-failure"));
    assert!(TRANSPORT_SERVICE.contains("Type=notify"));
    assert!(TRANSPORT_SERVICE.contains("CapabilityBoundingSet=CAP_NET_ADMIN"));
    for unit in [KILL_SWITCH_SERVICE, RECONNECT_SERVICE, TRANSPORT_SERVICE] {
        assert!(unit.contains("StandardOutput=null"));
        assert!(unit.contains("StandardError=null"));
    }
}

#[test]
fn default_route_fingerprint_is_normalized_and_ignores_the_vpn_interface() {
    let first = default_route_fingerprint(
        "default via 192.0.2.1 dev wlan0 metric 600\n\
         default via 198.51.100.1 dev eth0 metric 100\n",
    );
    let reordered = default_route_fingerprint(
        "  default   via 198.51.100.1 dev eth0 metric 100\n\
         default via 192.0.2.1 dev wlan0 metric 600\n",
    );

    assert_eq!(first, reordered);
    assert_ne!(
        first,
        default_route_fingerprint("default via 203.0.113.1 dev eth0 metric 100\n")
    );
    assert_eq!(
        default_route_fingerprint("default dev sirinvpn0 metric 1\n"),
        None
    );
}

#[test]
fn network_epoch_tracks_only_a_live_route_transition_and_fresh_handshake() {
    let mut tracker = NetworkEpochTracker::default();
    tracker.observe(Some(11), Some(100), 120);
    assert_eq!(
        tracker.context(),
        SupervisorContext {
            network_changed_at_unix: None,
            physical_route_available: Some(true),
            route_transition: None,
        }
    );

    tracker.observe(None, Some(100), 121);
    assert_eq!(tracker.context().physical_route_available, Some(false));
    assert_eq!(tracker.context().route_transition, None);

    tracker.observe(Some(22), Some(100), 122);
    assert_eq!(
        tracker.context().route_transition,
        Some(RouteTransition {
            detected_at_unix: 122,
            prior_handshake_unix: 100,
        })
    );

    tracker.observe(Some(22), Some(100), 123);
    assert!(tracker.context().route_transition.is_some());
    tracker.observe(Some(22), Some(101), 124);
    assert_eq!(tracker.context().route_transition, None);
}

#[test]
fn route_loss_holds_persistent_state_without_rebuild_churn() {
    let directory = tempfile::tempdir().unwrap();
    let runner = RecordingRunner {
        emulate_tunnel: true,
        ..RecordingRunner::default()
    };
    let helper = LinuxNetworkHelper::new(runner.clone(), directory.path().to_path_buf());
    helper.connect(&persistent_automatic_request()).unwrap();
    let mut state = helper.read_state().unwrap();
    state.applied_at_unix = now_unix().saturating_sub(HANDSHAKE_GRACE_SECONDS);
    helper.write_state(&state).unwrap();
    runner.commands.lock().unwrap().clear();

    assert_eq!(
        helper
            .reconcile_persistent_once_with_context(
                true,
                SupervisorContext {
                    network_changed_at_unix: None,
                    physical_route_available: Some(false),
                    route_transition: None,
                },
            )
            .unwrap(),
        ReconcileOutcome::AwaitingHandshake
    );
    assert_eq!(
        helper.read_state().unwrap().transport,
        TransportKind::DirectUdp
    );
    assert!(runner.interface_exists.load(Ordering::SeqCst));
    assert!(
        runner
            .commands
            .lock()
            .unwrap()
            .iter()
            .all(|(program, arguments, _)| program != "ip"
                || arguments != &["link", "delete", INTERFACE_NAME])
    );
}
