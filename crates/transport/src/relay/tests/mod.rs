use super::*;

use std::sync::atomic::{AtomicBool, Ordering};

fn keypair() -> snow::Keypair {
    let parameters: NoiseParams = NOISE_PATTERN.parse().unwrap();
    Builder::new(parameters).generate_keypair().unwrap()
}

mod a_pinned_relay_ignores_other_local_senders;
mod replay_window_accepts_reordering_once_and_rejects_old_packets;

#[test]
fn probe_limiter_admits_new_sources_when_its_table_is_full() {
    let mut limiter = ProbeLimiter::default();
    for index in 0..PROBE_SOURCES as u32 {
        assert!(limiter.allow(IpAddr::V4(std::net::Ipv4Addr::from(0x0a00_0000 + index))));
    }
    // The flood has used this second's global budget.
    assert!(!limiter.allow("192.0.2.1".parse().unwrap()));
    // In the next second a new source is admitted although every window is still recent.
    limiter.global = None;
    assert!(limiter.allow("192.0.2.1".parse().unwrap()));
    assert_eq!(limiter.peers.len(), PROBE_SOURCES);
}

#[test]
fn probe_limiter_groups_ipv6_by_prefix_and_keeps_mapped_ipv4_separate() {
    let mut limiter = ProbeLimiter::default();
    for host in 1..=PROBE_ATTEMPTS_PER_SOURCE {
        assert!(limiter.allow(format!("2001:db8::{host:x}").parse().unwrap()));
    }
    assert!(!limiter.allow("2001:db8::ffff".parse().unwrap()));
    assert!(limiter.allow("2001:db8:0:1::1".parse().unwrap()));
    assert!(limiter.allow("::ffff:192.0.2.1".parse().unwrap()));
    assert!(limiter.allow("::ffff:192.0.2.2".parse().unwrap()));
}

#[test]
fn obfuscated_udp_mtu_ceiling_matches_the_largest_relayed_packet() {
    // A WireGuard data packet is the tunnel MTU plus 32 bytes.
    assert_eq!(
        usize::from(crate::OBFUSCATED_UDP_MAX_MTU) + 32,
        MAX_INNER_PACKET_LENGTH
    );
}

fn stamped(timestamp: Duration) -> Vec<u8> {
    let mut payload = HANDSHAKE_TIMESTAMP_MARKER.to_vec();
    payload.extend_from_slice(&timestamp.as_secs().to_be_bytes());
    payload.extend_from_slice(&0_u32.to_be_bytes());
    payload.extend_from_slice(&[9; 40]);
    payload
}

/// A future stamp is refused past the same day the age limit allows, with its own reason.
#[test]
fn a_far_future_handshake_is_refused() {
    let mut cache = HandshakeReplayCache::default();
    let client = [7_u8; 32];
    let ahead = HANDSHAKE_MAX_AGE + Duration::from_secs(3_600);
    assert!(matches!(
        cache.accept_client_handshake(b"far", client, &stamped(unix_now() + ahead)),
        Err(HandshakeRefusal::TimestampTooFarAhead { ahead: refused })
            if refused >= HANDSHAKE_MAX_AGE
    ));
    assert!(
        cache
            .accept_client_handshake(
                b"near",
                client,
                &stamped(unix_now() + Duration::from_secs(3_600))
            )
            .is_ok()
    );
}

/// Before, the digest was forgotten 180 s after arrival, and `latest` is clamped to the
/// server clock, so the same future-stamped message was accepted again every 180 s.
#[test]
fn a_future_stamped_handshake_is_not_accepted_again_while_it_is_fresh() {
    let mut cache = HandshakeReplayCache::default();
    let client = [7_u8; 32];
    let payload = stamped(unix_now() + Duration::from_secs(3_600));
    let start = Instant::now();
    assert!(
        cache
            .check_client_handshake(b"ahead", client, &payload, start)
            .is_ok()
    );
    for later in [181, 1_800, 3_600] {
        assert_eq!(
            cache.check_client_handshake(
                b"ahead",
                client,
                &payload,
                start + Duration::from_secs(later)
            ),
            Err(HandshakeRefusal::Replayed)
        );
    }
    // Present-time digests still expire after the usual window.
    assert!(cache.insert_until(b"now", start, start + SESSION_IDLE_TIMEOUT));
    assert!(!cache.insert_until(b"now", start + Duration::from_secs(179), start));
    assert!(cache.insert_until(b"now", start + Duration::from_secs(181), start));
}

#[test]
fn a_channel_binding_is_found_only_where_the_client_put_it() {
    let binding = [5_u8; 32];
    let payload = client_handshake_payload_bound(&binding);
    let stamp = handshake_timestamp(&payload).unwrap();
    assert!(stamp.as_secs().abs_diff(unix_now().as_secs()) <= 1);
    assert!(handshake_is_bound(&payload, &binding));
    assert!(!handshake_is_bound(&payload, &[6_u8; 32]));
    assert!(!handshake_is_bound(&client_handshake_payload(), &binding));
}

/// Handshakes the replay cache no longer remembers still complete, so they must not end
/// the device's live session: only a session whose packets decrypt takes a slot.
#[tokio::test]
async fn replayed_handshakes_do_not_end_a_live_udp_session() {
    let server = keypair();
    let client = keypair();
    let backend = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let public_address = UdpSocket::bind("127.0.0.1:0")
        .await
        .unwrap()
        .local_addr()
        .unwrap();
    let authorized = AuthorizedPeers::default();
    authorized.replace([<[u8; 32]>::try_from(client.public.as_slice()).unwrap()]);
    let server_task = tokio::spawn(run_server_relay(
        ServerRelayConfig {
            listen: SocketAddr::new("0.0.0.0".parse().unwrap(), public_address.port()),
            wireguard_backend: backend.local_addr().unwrap(),
            server_private_key: Zeroizing::new(
                <[u8; 32]>::try_from(server.private.as_slice()).unwrap(),
            ),
        },
        authorized,
        ActiveTransportRegistry::default(),
    ));
    let local_address = UdpSocket::bind("127.0.0.1:0")
        .await
        .unwrap()
        .local_addr()
        .unwrap();
    let ready = Arc::new(AtomicBool::new(false));
    let ready_clone = ready.clone();
    let client_task = tokio::spawn(run_client_relay(
        ClientRelayConfig {
            local_listen: local_address,
            server_address: public_address,
            socket_mark: None,
            client_private_key: STANDARD.encode(&client.private),
            server_public_key: STANDARD.encode(&server.public),
        },
        move || ready_clone.store(true, Ordering::Release),
    ));
    timeout(Duration::from_secs(5), async {
        while !ready.load(Ordering::Acquire) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    let wireguard = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut buffer = [0_u8; 128];
    let mut round_trip = async |body: &[u8]| {
        wireguard.send_to(body, local_address).await.unwrap();
        let (length, _) = timeout(Duration::from_secs(2), backend.recv_from(&mut buffer))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buffer[..length], body);
    };
    round_trip(b"live").await;

    let attacker = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let client_private = <[u8; 32]>::try_from(client.private.as_slice()).unwrap();
    let server_public = <[u8; 32]>::try_from(server.public.as_slice()).unwrap();
    for _ in 0..=MAX_SESSIONS_PER_CLIENT {
        let mut handshake = initiator_handshake(&client_private, &server_public).unwrap();
        let mut request = [0_u8; HANDSHAKE_MAX_LENGTH];
        let length = handshake
            .write_message(&client_handshake_payload(), &mut request)
            .unwrap();
        attacker
            .send_to(&request[..length], public_address)
            .await
            .unwrap();
        timeout(Duration::from_secs(1), attacker.recv_from(&mut [0_u8; 512]))
            .await
            .unwrap()
            .unwrap();
    }
    round_trip(b"still live").await;
    client_task.abort();
    server_task.abort();
}
