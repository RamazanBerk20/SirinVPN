use super::*;
fn reply(received: u8, average: u32) -> Vec<u8> {
    format!("8 packets transmitted, {received} received, 0% packet loss, time 1400ms\nrtt min/avg/max/mdev = 1.0/{average}.0/200.0/1.0 ms\n").into_bytes()
}

#[test]
fn recovery_requires_repeated_failed_checks_without_receive_progress() {
    let mut health = PathHealth::default();
    health.record(100, Some(10), Some(90), false);
    for at in [105, 110, 115] {
        health.record(at, Some(10), Some(90), false);
        assert!(!health.failed(at));
    }
    health.record(120, Some(10), Some(90), false);
    assert!(health.failed(120));
    health.record(125, Some(11), Some(90), false);
    assert!(!health.failed(125));
    assert!(health.receiving(125));
    // A service answering over WireGuard is sufficient with ICMP filtered.
    for at in [130, 140, 150, 160] {
        health.record(at, Some(11), Some(90), true);
    }
    assert!(!health.failed(160));
    // Rekey, counter reset and clock reversal all clear stale failure evidence.
    health.record(165, Some(11), Some(165), false);
    assert!(health.receiving(165));
    health.record(170, Some(0), Some(0), false);
    assert!(!health.failed(170));
    health.record(50, Some(0), Some(0), false);
    assert!(!health.failed(50));
    for at in [55, 60, 65, 70] {
        health.record(at, Some(0), Some(0), false);
    }
    assert!(health.failed(70));
    health.record(200, Some(0), Some(0), false);
    assert!(
        !health.failed(200),
        "resume must discard old failure evidence"
    );
}

#[test]
fn transmit_bytes_alone_do_not_prove_delivery() {
    assert_eq!(receive_counter(b"peer 3 999\n"), Some(3));
    assert_eq!(receive_counter(b"bad\n"), None);
    assert_eq!(receive_counter(b""), None);
}

#[test]
fn old_disruptive_trial_state_cannot_restart_a_trial() {
    let quality: QualityController = serde_json::from_value(serde_json::json!({
        "status": { "sample": null, "selection": "comparing", "candidates_checked": 2 },
        "sampled_at": 1, "cycle_started_at": 1, "rollback": "direct_udp",
        "checked": ["direct_udp", "tls_like"], "best": null
    }))
    .unwrap();
    assert!(quality.valid());
    assert_eq!(quality.snapshot(true).selection, QualitySelection::Pending);
    assert!(!quality.health.failed(100));
}

#[test]
fn complete_delivery_wins_over_speed_and_hysteresis_rejects_noise() {
    let slow = parse_sample(&reply(8, 50), TransportKind::DirectUdp).unwrap();
    let fast_lossy = parse_sample(&reply(7, 5), TransportKind::TlsLike).unwrap();
    assert!(!fast_lossy.improves(slow));
    assert!(slow.improves(fast_lossy));
    let noise = parse_sample(&reply(8, 49), TransportKind::TlsLike).unwrap();
    assert!(!noise.improves(slow));
    let fast = parse_sample(&reply(8, 20), TransportKind::TlsLike).unwrap();
    assert!(fast.improves(slow));
    assert!(parse_sample(b"malformed", TransportKind::DirectUdp).is_none());
}

#[test]
#[ignore = "requires a disposable network namespace; use tests/network/run-transport-quality.sh"]
fn kernel_quality_measures_the_private_wireguard_path_and_reports_blocked_icmp() {
    assert_eq!(
        std::env::var("SIRINVPN_POLICY_ISOLATED").as_deref(),
        Ok("1")
    );
    assert!(Path::new("/.dockerenv").exists());
    let run = |mode| {
        assert!(
            Command::new("python3")
                .args(["tests/network/mtu_path.py", mode])
                .status()
                .unwrap()
                .success()
        )
    };
    run("prepare");
    let directory = tempfile::tempdir().unwrap();
    let helper = LinuxNetworkHelper::new(SystemRunner, directory.path().into());
    let request = crate::tests::request();
    let sample = helper.sample_quality(&request).unwrap();
    assert!(sample.stable());
    assert!(sample.latency_micros > 0);
    run("block");
    assert!(helper.sample_quality(&request).is_none());
}
