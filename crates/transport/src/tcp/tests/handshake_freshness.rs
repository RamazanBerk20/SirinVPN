use super::*;

fn stamped(seconds: u64, padding: u8) -> Vec<u8> {
    let mut payload = b"SVPNts01".to_vec();
    payload.extend_from_slice(&seconds.to_be_bytes());
    payload.extend_from_slice(&0_u32.to_be_bytes());
    payload.extend_from_slice(&[padding; 40]);
    payload
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[test]
fn client_payloads_carry_a_current_timestamp() {
    let payload = client_handshake_payload();
    assert!((48..=144).contains(&payload.len()));
    assert_eq!(&payload[..8], b"SVPNts01");
    let seconds = u64::from_be_bytes(payload[8..16].try_into().unwrap());
    assert!(seconds.abs_diff(now()) <= 1);
}

#[test]
fn older_handshakes_are_rejected_after_a_newer_one() {
    let client = [7_u8; 32];
    let mut cache = HandshakeReplayCache::default();
    let base = now();
    // Messages differ, as distinct Noise messages always do.
    assert!(cache.accept_client_handshake(b"m1", client, &stamped(base - 300, 1)));
    assert!(cache.accept_client_handshake(b"m2", client, &stamped(base, 2)));
    // Reordered concurrent carriers stay within the tolerance.
    assert!(cache.accept_client_handshake(b"m3", client, &stamped(base - 5, 3)));
    // A replay captured minutes ago is no longer fresh even after the digest window.
    assert!(!cache.accept_client_handshake(b"m4", client, &stamped(base - 300, 4)));
    // The same message is never accepted twice.
    assert!(!cache.accept_client_handshake(b"m2", client, &stamped(base, 2)));
    // Another client's history is independent.
    assert!(cache.accept_client_handshake(b"m5", [8_u8; 32], &stamped(base - 300, 5)));
}

#[test]
fn unmarked_handshakes_stay_valid_only_for_clients_that_never_sent_a_timestamp() {
    let client = [7_u8; 32];
    let mut cache = HandshakeReplayCache::default();
    assert!(cache.accept_client_handshake(b"legacy-1", client, &[0x55; 64]));
    assert!(cache.accept_client_handshake(b"stamped", client, &stamped(now(), 1)));
    assert!(!cache.accept_client_handshake(b"legacy-2", client, &[0x56; 64]));
}

#[test]
fn a_client_clock_that_ran_ahead_is_accepted_again_after_correction() {
    let client = [7_u8; 32];
    let mut cache = HandshakeReplayCache::default();
    assert!(cache.accept_client_handshake(b"ahead", client, &stamped(now() + 3_600, 1)));
    assert!(cache.accept_client_handshake(b"corrected", client, &stamped(now(), 2)));
}
