use super::*;

#[test]
fn route_transition_allows_roaming_then_cycles_automatic_transport() {
    let directory = tempfile::tempdir().unwrap();
    let runner = RecordingRunner {
        emulate_tunnel: true,
        ..RecordingRunner::default()
    };
    let helper = LinuxNetworkHelper::new(runner.clone(), directory.path().to_path_buf());
    helper.connect(&persistent_automatic_request()).unwrap();
    let now = now_unix();
    let prior_handshake = now.saturating_sub(1);
    runner
        .latest_handshake_unix
        .store(prior_handshake, Ordering::SeqCst);
    let mut state = helper.read_state().unwrap();
    state.applied_at_unix = now.saturating_sub(HANDSHAKE_GRACE_SECONDS);
    helper.write_state(&state).unwrap();

    let grace = SupervisorContext {
        network_changed_at_unix: None,
        physical_route_available: Some(true),
        route_transition: Some(RouteTransition {
            detected_at_unix: now,
            prior_handshake_unix: prior_handshake,
        }),
    };
    assert_eq!(
        helper
            .reconcile_persistent_once_with_context(true, grace)
            .unwrap(),
        ReconcileOutcome::AwaitingHandshake
    );
    assert_eq!(
        helper.read_state().unwrap().transport,
        TransportKind::DirectUdp
    );

    let expired = SupervisorContext {
        route_transition: grace.route_transition.map(|transition| RouteTransition {
            detected_at_unix: transition
                .detected_at_unix
                .saturating_sub(HANDSHAKE_GRACE_SECONDS),
            ..transition
        }),
        ..grace
    };
    assert_eq!(
        helper
            .reconcile_persistent_once_with_context(true, expired)
            .unwrap(),
        ReconcileOutcome::AwaitingHandshake
    );
    assert_eq!(
        helper.read_state().unwrap().transport,
        TransportKind::ObfuscatedUdp
    );
}

#[test]
fn post_transition_handshake_keeps_the_current_transport() {
    let directory = tempfile::tempdir().unwrap();
    let runner = RecordingRunner {
        emulate_tunnel: true,
        ..RecordingRunner::default()
    };
    let helper = LinuxNetworkHelper::new(runner.clone(), directory.path().to_path_buf());
    helper.connect(&persistent_automatic_request()).unwrap();
    let now = now_unix();
    runner.latest_handshake_unix.store(now, Ordering::SeqCst);

    assert_eq!(
        helper
            .reconcile_persistent_once_with_context(
                true,
                SupervisorContext {
                    network_changed_at_unix: None,
                    physical_route_available: Some(true),
                    route_transition: Some(RouteTransition {
                        detected_at_unix: now.saturating_sub(HANDSHAKE_GRACE_SECONDS),
                        prior_handshake_unix: now.saturating_sub(1),
                    }),
                },
            )
            .unwrap(),
        ReconcileOutcome::Healthy
    );
    let state = helper.read_state().unwrap();
    assert_eq!(state.transport, TransportKind::DirectUdp);
    assert!(!state.reconnecting);
}

#[test]
fn latest_handshake_parser_uses_the_newest_peer_value() {
    assert_eq!(
        latest_handshake(b"first-key\t17\nsecond-key\t42\n"),
        Some(42)
    );
    assert_eq!(latest_handshake(b"first-key\t0\n"), Some(0));
    assert_eq!(latest_handshake(b""), None);
}

#[test]
fn ipv6_status_token_matching_is_exact() {
    let output = b"7: sirinvpn0    inet6 fd12:3456::2/128 scope global\n";
    assert!(output_contains_token(output, "fd12:3456::2/128"));
    assert!(!output_contains_token(output, "fd12:3456::2"));
    assert!(!output_contains_token(output, "fd12:3456::3/128"));
}

#[test]
fn handshake_window_does_not_preempt_wireguard_rekey() {
    let now = 1_000;
    assert!(handshake_timestamp_is_recent(819, now));
    assert!(!handshake_timestamp_is_recent(759, now));
    let transition = RouteTransition {
        detected_at_unix: now,
        prior_handshake_unix: 900,
    };
    assert!(!established_handshake_is_healthy(
        Some(900),
        now,
        Some(transition)
    ));
    assert!(established_handshake_is_healthy(
        Some(901),
        now,
        Some(transition)
    ));
}
