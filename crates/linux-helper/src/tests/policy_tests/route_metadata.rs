use super::*;

const WIFI: &str = "default via 192.168.1.1 dev wlo1 proto dhcp src 192.168.1.9 metric 600";
const PENALIZED_WIFI: &str =
    "default via 192.168.1.1 dev wlo1 proto dhcp src 192.168.1.9 metric 20600";

#[test]
fn connectivity_metric_penalty_and_lease_countdown_do_not_change_the_network_path() {
    assert_eq!(
        default_route_fingerprint(WIFI),
        default_route_fingerprint(PENALIZED_WIFI)
    );
    assert_eq!(
        default_route_fingerprint(&format!("{WIFI} expires 299sec")),
        default_route_fingerprint(&format!("{PENALIZED_WIFI} expires 298sec"))
    );
    assert_eq!(
        default_route_fingerprint(WIFI),
        default_route_fingerprint(&WIFI.replace("proto dhcp", "proto static"))
    );
}

#[test]
fn route_preference_changes_matter_when_they_select_a_different_path() {
    let ethernet = "default via 10.1.0.1 dev eth0 src 10.1.0.2 metric 100";
    let selected = default_route_fingerprint(&format!("{WIFI}\n{ethernet}"));
    assert_eq!(selected, default_route_fingerprint(ethernet));
    assert_eq!(
        selected,
        default_route_fingerprint(&format!("{PENALIZED_WIFI}\n{ethernet}"))
    );
    assert_ne!(
        selected,
        default_route_fingerprint(&format!(
            "{WIFI}\n{}",
            ethernet.replace("metric 100", "metric 20100")
        ))
    );
    for changed in [
        WIFI.replace("192.168.1.1 ", "192.168.1.254 "),
        WIFI.replace("dev wlo1", "dev eth0"),
        WIFI.replace("src 192.168.1.9", "src 192.168.1.10"),
    ] {
        assert_ne!(
            default_route_fingerprint(WIFI),
            default_route_fingerprint(&changed)
        );
    }
}

#[test]
fn a_metric_penalty_does_not_cycle_a_healthy_direct_udp_connection() {
    let dir = tempfile::tempdir().unwrap();
    let runner = runner();
    let helper = LinuxNetworkHelper::new(runner.clone(), dir.path().to_owned());
    let mut request = independent(true, true, false);
    request.reconnect_candidates = persistent_automatic_request().reconnect_candidates.clone();
    helper.connect(&request).unwrap();
    expire(&helper, true);
    let now = now_unix();
    let handshake = now.saturating_sub(90);
    runner
        .base
        .latest_handshake_unix
        .store(handshake, Ordering::SeqCst);
    let mut network = NetworkEpochTracker::default();
    network.observe(
        default_route_fingerprint(WIFI),
        Some(handshake),
        now.saturating_sub(32),
    );
    network.observe(
        default_route_fingerprint(PENALIZED_WIFI),
        Some(handshake),
        now.saturating_sub(31),
    );
    let before = helper.read_state().unwrap();
    runner.base.commands.lock().unwrap().clear();
    assert_eq!(
        helper
            .reconcile_persistent_once_with_context(true, network.context())
            .unwrap(),
        ReconcileOutcome::Healthy
    );
    let after = helper.read_state().unwrap();
    assert_eq!(after.transport, TransportKind::DirectUdp);
    assert_eq!(after.applied_at_unix, before.applied_at_unix);
    assert_eq!(after.initial_attempts, before.initial_attempts);
    assert!(runner.base.guard_exists.load(Ordering::SeqCst));
    assert!(
        !runner
            .base
            .commands
            .lock()
            .unwrap()
            .iter()
            .any(|(p, a, _)| p == "ip" && a == &["link", "delete", INTERFACE_NAME])
    );
}
