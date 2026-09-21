use super::*;

#[tokio::test]
#[ignore = "requires disposable networking; use tests/network/run-peer-activity.sh"]
async fn kernel_peer_activity_uses_actual_handshakes() {
    assert_eq!(
        std::env::var("SIRINVPN_POLICY_ISOLATED").as_deref(),
        Ok("1")
    );
    assert!(Path::new("/.dockerenv").exists());
    let output = Command::new("python3")
        .args(["tests/network/peer_activity.py", "prepare"])
        .output()
        .await
        .unwrap();
    assert!(output.status.success(), "isolated peer setup failed");
    let keys: Vec<String> = serde_json::from_slice(&output.stdout).unwrap();
    let before = recent_peer_activity("sirinvpn0").await.unwrap();
    assert_eq!(count_recent_authorized(&before, &keys), Some(0));
    assert!(
        Command::new("python3")
            .args(["tests/network/peer_activity.py", "connect"])
            .status()
            .await
            .unwrap()
            .success()
    );
    let after = recent_peer_activity("sirinvpn0").await.unwrap();
    assert_eq!(count_recent_authorized(&after, &keys), Some(1));
    assert_eq!(after.get(&keys[0]), Some(&true));
    assert_eq!(after.get(&keys[1]), Some(&false));
    // Removing an authorization cannot turn it into a connected authorized device.
    assert_eq!(count_recent_authorized(&after, &keys[1..]), Some(0));
    assert_eq!(
        count_recent_authorized(&after, &[STANDARD.encode([19_u8; 32])]),
        None
    );
    assert!(recent_peer_activity("missing-interface").await.is_none());
    println!(
        "real WireGuard: 0 active before handshake, 1/2 afterwards; missing and unauthorized peers handled separately"
    );
}
