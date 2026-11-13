use super::*;

fn tcp(kill: bool, reconnect: bool) -> TunnelConnectRequest {
    let mut request = independent(kill, reconnect, false);
    request.endpoint_port = 443;
    request.transport = TransportKind::TcpFallback;
    request.server_transport_public_key = Some(STANDARD.encode([9_u8; 32]));
    request.mtu = 1_280;
    request
}

/// The interface's WireGuard port is fixed and every relay config names it, so the relay
/// can drop datagrams from any other local process.
#[test]
fn carrier_relays_are_pinned_to_the_fixed_wireguard_port() {
    let dir = tempfile::tempdir().unwrap();
    let runner = runner();
    let helper = LinuxNetworkHelper::new(runner.clone(), dir.path().join("run"));
    helper.connect(&tcp(true, true)).unwrap();
    let bytes = fs::read(helper.carrier_config_path(TransportKind::TcpFallback)).unwrap();
    let ClientTransportConfig::Pinned(PinnedClientTransportConfig {
        wireguard,
        carrier: CurrentClientTransportConfig::TcpFallback(config),
    }) = serde_json::from_slice(&bytes).unwrap()
    else {
        panic!("the helper must write a pinned relay configuration");
    };
    assert_eq!(
        wireguard,
        SocketAddr::from(([127, 0, 0, 1], WIREGUARD_LISTEN_PORT))
    );
    assert_eq!(config.local_listen.port(), TCP_CLIENT_RELAY_PORT);
    let commands = runner.base.commands.lock().unwrap();
    assert!(commands.iter().any(|(program, arguments, _)| {
        program == "wg"
            && arguments.first().map(String::as_str) == Some("set")
            && arguments.windows(2).any(|pair| {
                pair[0] == "listen-port" && pair[1] == WIREGUARD_LISTEN_PORT.to_string()
            })
    }));
}

/// An occupied relay port is reported and pauses the session with its guard kept; the
/// supervisor never moves on to another carrier (ultimately plain WireGuard) because of it.
#[test]
fn an_occupied_carrier_port_is_reported_instead_of_falling_back() {
    let dir = tempfile::tempdir().unwrap();
    let runner = runner();
    runner.squatted.store(true, Ordering::SeqCst);
    let helper = LinuxNetworkHelper::new(runner.clone(), dir.path().join("run"));
    let mut request = tcp(true, true);
    request.reconnect_candidates = vec![
        ReconnectCandidate {
            transport: TransportKind::TcpFallback,
            endpoint_port: 443,
            server_transport_public_key: Some(STANDARD.encode([9_u8; 32])),
            https: None,
            server_certificate_sha256: None,
            mtu: 1_280,
        },
        ReconnectCandidate {
            transport: TransportKind::DirectUdp,
            endpoint_port: 51_820,
            server_transport_public_key: None,
            https: None,
            server_certificate_sha256: None,
            mtu: 1_420,
        },
    ];
    let error = helper.connect(&request).unwrap_err();
    assert!(
        matches!(&error, HelperError::InvalidConfiguration(message) if message.contains(&TCP_CLIENT_RELAY_PORT.to_string())),
        "{error:?}"
    );
    let state = helper.read_state().unwrap();
    assert!(state.waiting_for_user);
    assert_eq!(state.transport, TransportKind::TcpFallback);
    assert!(runner.base.guard_exists.load(Ordering::SeqCst));
    // Later supervisor passes stay paused on the same carrier.
    for _ in 0..3 {
        helper.reconcile_persistent_once(true).unwrap();
    }
    let state = helper.read_state().unwrap();
    assert!(state.waiting_for_user);
    assert_eq!(state.transport, TransportKind::TcpFallback);
    assert!(
        !runner
            .base
            .commands
            .lock()
            .unwrap()
            .iter()
            .any(|(program, arguments, _)| {
                program == "wg"
                    && arguments
                        .iter()
                        .any(|argument| argument == "203.0.113.8:51820")
            })
    );
}

fn listen_port_commands(runner: &PolicyRunner) -> Vec<Vec<String>> {
    runner
        .base
        .commands
        .lock()
        .unwrap()
        .iter()
        .filter(|(program, arguments, _)| {
            program == "wg" && arguments.iter().any(|argument| argument == "listen-port")
        })
        .map(|(_, arguments, _)| arguments.clone())
        .collect()
}

fn direct_then_tcp() -> TunnelConnectRequest {
    let mut request = independent(true, true, false);
    request.reconnect_candidates = vec![
        ReconnectCandidate {
            transport: TransportKind::DirectUdp,
            endpoint_port: 51_820,
            server_transport_public_key: None,
            https: None,
            server_certificate_sha256: None,
            mtu: 1_420,
        },
        ReconnectCandidate {
            transport: TransportKind::TcpFallback,
            endpoint_port: 443,
            server_transport_public_key: Some(STANDARD.encode([9_u8; 32])),
            https: None,
            server_certificate_sha256: None,
            mtu: 1_280,
        },
    ];
    request
}

/// Direct UDP has no relay to protect: a fixed privileged source port on the outer path
/// would only be a fingerprint, so WireGuard keeps the kernel's ephemeral port.
#[test]
fn direct_udp_keeps_an_ephemeral_wireguard_port() {
    let dir = tempfile::tempdir().unwrap();
    let runner = runner();
    let helper = LinuxNetworkHelper::new(runner.clone(), dir.path().join("run"));
    helper.connect(&independent(true, true, false)).unwrap();
    assert!(listen_port_commands(&runner).is_empty());
}

/// A live handoff from Direct UDP to a relay fixes the port before the relay starts.
#[test]
fn a_handoff_to_a_relay_fixes_the_wireguard_port_first() {
    let dir = tempfile::tempdir().unwrap();
    let runner = runner();
    runner
        .base
        .latest_handshake_unix
        .store(now_unix(), Ordering::SeqCst);
    let helper = LinuxNetworkHelper::new(runner.clone(), dir.path().join("run"));
    helper.connect(&direct_then_tcp()).unwrap();
    helper.reconcile_persistent_once(true).unwrap();
    assert!(listen_port_commands(&runner).is_empty());
    let desired = helper.read_persistent().unwrap();
    let mut state = helper.read_state().unwrap();
    let next =
        request_for_reconnect_candidate(&desired.request, &desired.request.reconnect_candidates[1]);
    runner.base.commands.lock().unwrap().clear();
    helper
        .change_quality_transport(&desired, &next, &mut state)
        .unwrap();
    assert_eq!(state.transport, TransportKind::TcpFallback);
    let commands = runner.base.commands.lock().unwrap().clone();
    let pinned = commands
        .iter()
        .position(|(program, arguments, _)| {
            program == "wg" && arguments == &["set", INTERFACE_NAME, "listen-port", "1023"]
        })
        .expect("the port is fixed on the live interface");
    let started = commands
        .iter()
        .position(|(program, arguments, _)| {
            program == "systemctl"
                && arguments == &["start", "sirinvpn-transport@tcp_fallback.service"]
        })
        .unwrap();
    assert!(pinned < started);
}

/// Before, a taken WireGuard port was a generic WireGuard failure (and the supervisor
/// moved on); now it is the same clear, paused error as a taken relay port.
#[test]
fn a_taken_wireguard_port_is_reported_like_a_taken_relay_port() {
    let dir = tempfile::tempdir().unwrap();
    let runner = runner();
    runner.wireguard_port_taken.store(true, Ordering::SeqCst);
    let helper = LinuxNetworkHelper::new(runner.clone(), dir.path().join("run"));
    let error = helper.connect(&tcp(true, true)).unwrap_err();
    assert!(
        matches!(&error, HelperError::InvalidConfiguration(message)
            if message.contains("another program") && message.contains("1023")),
        "{error:?}"
    );
    let state = helper.read_state().unwrap();
    assert!(state.waiting_for_user);
    assert!(runner.base.guard_exists.load(Ordering::SeqCst));
    // Direct UDP does not need the port, so it is unaffected.
    let dir = tempfile::tempdir().unwrap();
    let runner = self::runner();
    runner.wireguard_port_taken.store(true, Ordering::SeqCst);
    let helper = LinuxNetworkHelper::new(runner, dir.path().join("run"));
    helper.connect(&independent(true, true, false)).unwrap();
}

/// Before, a handoff from a relay back to Direct UDP kept the fixed privileged port, so
/// outer packets left from source port 1023. The port goes back to random once the old
/// relay is no longer needed for rollback.
#[test]
fn a_handoff_to_direct_udp_gives_wireguard_a_random_port_again() {
    let dir = tempfile::tempdir().unwrap();
    let runner = runner();
    runner
        .base
        .latest_handshake_unix
        .store(now_unix(), Ordering::SeqCst);
    let helper = LinuxNetworkHelper::new(runner.clone(), dir.path().join("run"));
    let mut request = tcp(true, true);
    request.reconnect_candidates = direct_then_tcp().reconnect_candidates.clone();
    request.reconnect_candidates.reverse();
    helper.connect(&request).unwrap();
    helper.reconcile_persistent_once(true).unwrap();
    let desired = helper.read_persistent().unwrap();
    let mut state = helper.read_state().unwrap();
    assert_eq!(state.transport, TransportKind::TcpFallback);
    let next =
        request_for_reconnect_candidate(&desired.request, &desired.request.reconnect_candidates[1]);
    assert_eq!(next.transport, TransportKind::DirectUdp);
    runner.base.commands.lock().unwrap().clear();
    helper
        .change_quality_transport(&desired, &next, &mut state)
        .unwrap();
    assert_eq!(state.transport, TransportKind::DirectUdp);
    let commands = runner.base.commands.lock().unwrap().clone();
    let stopped = commands
        .iter()
        .position(|(program, arguments, _)| {
            program == "systemctl"
                && arguments == &["stop", "sirinvpn-transport@tcp_fallback.service"]
        })
        .expect("the old relay stops");
    let random = commands
        .iter()
        .position(|(program, arguments, _)| {
            program == "wg" && arguments == &["set", INTERFACE_NAME, "listen-port", "0"]
        })
        .expect("WireGuard gets a random port again");
    assert!(stopped < random);
    assert_eq!(listen_port_commands(&runner).len(), 1);
}
