use super::*;

use std::sync::atomic::{AtomicBool, Ordering};

fn keypair() -> snow::Keypair {
    let parameters: NoiseParams = NOISE_PATTERN.parse().unwrap();
    Builder::new(parameters).generate_keypair().unwrap()
}

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
