//! On-demand leak checks that use only this device's own VPS. Internet-bound IPv4/IPv6 test
//! requests go to documentation addresses the VPS answers only through the tunnel; the DNS test
//! looks up a one-off name only the VPS resolver answers. Nothing is stored on either side.
use super::{CurrentConnection, check};
use crate::{ManagementClient, SecretIdentity};
use sirinvpn_protocol::{
    DiagnosticCheck,
    DiagnosticLevel::{Fail, NotApplicable, Pass},
    LEAK_TEST_DNS_ZONE, LEAK_TEST_IPV4, LEAK_TEST_IPV6, ServerProfile, ipv6_tunnel_address,
};
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket},
    time::Duration,
};

const IPV4: (&str, &str, &str) = ("leak_ipv4", "IPv4 leak test", "IPv4");
const IPV6: (&str, &str, &str) = ("leak_ipv6", "IPv6 leak test", "IPv6");
const DNS: (&str, &str) = ("leak_dns", "DNS leak test");

pub async fn checks(
    profile: &ServerProfile,
    identity: &SecretIdentity,
    current: &CurrentConnection,
    client: &ManagementClient,
) -> Vec<DiagnosticCheck> {
    // A failed request is already explained by the management check.
    let Ok(configuration) = client.configuration().await else {
        return Vec::new();
    };
    if !configuration.leak_test_enabled {
        let message = "Your VPS can't run the leak test yet. Update or repair the VPS, then run diagnostics again.";
        return vec![
            check(IPV4.0, IPV4.1, NotApplicable, message),
            check(IPV6.0, IPV6.1, NotApplicable, message),
            check(DNS.0, DNS.1, NotApplicable, message),
        ];
    }
    let ipv6 = match profile.client_tunnel_address {
        IpAddr::V4(address) if profile.ipv6_tunnel_enabled && current.ipv6_tunneled => {
            ipv6_tunnel_address(profile.id, address).map(IpAddr::V6)
        }
        _ => None,
    };
    let (ipv4, ipv6, dns) = tokio::join!(
        family(
            profile,
            identity,
            current,
            IPV4,
            IpAddr::V4(LEAK_TEST_IPV4),
            Some(profile.client_tunnel_address)
        ),
        family(
            profile,
            identity,
            current,
            IPV6,
            IpAddr::V6(LEAK_TEST_IPV6),
            ipv6
        ),
        dns(profile, current),
    );
    vec![ipv4, ipv6, dns]
}

async fn family(
    profile: &ServerProfile,
    identity: &SecretIdentity,
    current: &CurrentConnection,
    (code, label, family): (&str, &str, &str),
    destination: IpAddr,
    expected: Option<IpAddr>,
) -> DiagnosticCheck {
    if let Some(message) = selected_only(current, family) {
        return check(code, label, NotApplicable, &message);
    }
    let route = route_source(destination);
    let Some(expected) = expected else {
        return untunneled_ipv6(route, current.ipv6_blocked);
    };
    let observed = match ManagementClient::for_leak_test(profile, identity, destination) {
        Ok(client) => client
            .leak_test_observation()
            .await
            .ok()
            .map(|observation| observation.source_address),
        Err(_) => None,
    };
    tunneled((code, label, family), expected, observed, route)
}

/// Selected routing sends other traffic outside the VPN on purpose; testing it would only send
/// a test request to the normal network.
fn selected_only(current: &CurrentConnection, family: &str) -> Option<String> {
    if current.split_applications {
        Some("Only the selected applications use this VPN, so this check doesn't apply to this device's own traffic.".into())
    } else if current.split_routes && family != "DNS" {
        Some(format!(
            "Only the selected subnets use this VPN, so other {family} traffic uses your normal network by design."
        ))
    } else {
        None
    }
}

/// The source address the operating system would use. Connecting a UDP socket sends nothing.
fn route_source(destination: IpAddr) -> Option<IpAddr> {
    let unspecified = match destination {
        IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
    };
    let socket = UdpSocket::bind(SocketAddr::new(unspecified, 0)).ok()?;
    socket.connect(SocketAddr::new(destination, 8443)).ok()?;
    Some(socket.local_addr().ok()?.ip())
}

fn tunneled(
    (code, label, family): (&str, &str, &str),
    expected: IpAddr,
    observed: Option<IpAddr>,
    route: Option<IpAddr>,
) -> DiagnosticCheck {
    let (level, message) = match observed {
        Some(source) if source == expected => (
            Pass,
            format!(
                "A request to an internet {family} address went through the VPN: your VPS received it from this device's VPN address."
            ),
        ),
        Some(_) => (
            Fail,
            format!(
                "Your VPS received the {family} test request from an address other than this device's VPN address. Reconnect, then run diagnostics again."
            ),
        ),
        None if route.is_some_and(|source| source != expected) => (
            Fail,
            format!(
                "This device sends internet {family} traffic outside the VPN, so websites can see your normal address unless the kill switch blocks it. Reconnect with full-tunnel routing and the kill switch on, then run diagnostics again."
            ),
        ),
        None => (
            Fail,
            format!(
                "The {family} test request didn't reach your VPS through the VPN, so this device's internet {family} traffic isn't confirmed to use it. Reconnect and run diagnostics again; if it keeps failing, repair the VPS."
            ),
        ),
    };
    check(code, label, level, &message)
}

/// Without an IPv6 tunnel the VPS cannot observe IPv6, so only a clear local leak fails.
fn untunneled_ipv6(route: Option<IpAddr>, blocked: bool) -> DiagnosticCheck {
    let (level, message) = match route {
        None => (
            NotApplicable,
            "This VPN doesn't carry IPv6, and this device has no IPv6 internet route, so no IPv6 traffic can leave outside the VPN.",
        ),
        Some(_) if blocked => (
            NotApplicable,
            "This VPN doesn't carry IPv6. The kill switch reports IPv6 blocked, but your VPS has no IPv6 tunnel to confirm it.",
        ),
        Some(_) => (
            Fail,
            "This device can send IPv6 outside the VPN, which doesn't carry IPv6, so IPv6 websites can see your normal address. Turn on the kill switch to block IPv6.",
        ),
    };
    check(IPV6.0, IPV6.1, level, message)
}

async fn dns(profile: &ServerProfile, current: &CurrentConnection) -> DiagnosticCheck {
    if let Some(message) = selected_only(current, "DNS") {
        return check(DNS.0, DNS.1, NotApplicable, &message);
    }
    // A fresh random label cannot be answered from any cache.
    let name = format!("{:032x}.{LEAK_TEST_DNS_ZONE}", rand::random::<u128>());
    let answers = tokio::time::timeout(
        Duration::from_secs(4),
        tokio::net::lookup_host((name.as_str(), 0)),
    )
    .await
    .ok()
    .and_then(Result::ok)
    .map(|addresses| addresses.map(|address| address.ip()).collect::<Vec<_>>())
    .unwrap_or_default();
    dns_result(&answers, profile.server_tunnel_address)
}

fn dns_result(answers: &[IpAddr], server: IpAddr) -> DiagnosticCheck {
    if answers.contains(&server) {
        check(
            DNS.0,
            DNS.1,
            Pass,
            "A one-off name looked up through this device's normal DNS was answered by your VPS resolver.",
        )
    } else {
        check(
            DNS.0,
            DNS.1,
            Fail,
            "A one-off name looked up through this device's normal DNS wasn't answered by your VPS resolver, so DNS queries go to another resolver, possibly outside the VPN. Check for a manually set DNS server or a local DNS service, then reconnect.",
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sirinvpn_protocol::{ConnectionState, DiagnosticLevel, TransportKind};

    fn current() -> CurrentConnection {
        CurrentConnection {
            state: ConnectionState::Connected,
            selected_server: true,
            another_server: false,
            recovering: false,
            waiting_for_user: false,
            protection: super::super::Protection::Armed,
            transport: Some(TransportKind::DirectUdp),
            split_routes: false,
            split_applications: false,
            ipv6_tunneled: false,
            ipv6_blocked: true,
            mtu: None,
            quality: None,
        }
    }

    #[test]
    fn only_a_request_seen_from_this_devices_vpn_address_passes() {
        let tunnel: IpAddr = "10.77.0.5".parse().unwrap();
        let physical: IpAddr = "192.168.1.20".parse().unwrap();
        let result = |observed, route| tunneled(IPV4, tunnel, observed, route);
        assert_eq!(
            result(Some(tunnel), Some(tunnel)).level,
            DiagnosticLevel::Pass
        );
        let other = result(Some("10.77.0.9".parse().unwrap()), Some(tunnel));
        assert_eq!(other.level, DiagnosticLevel::Fail);
        assert!(
            other
                .message
                .contains("other than this device's VPN address")
        );
        let outside = result(None, Some(physical));
        assert_eq!(outside.level, DiagnosticLevel::Fail);
        assert!(outside.message.contains("outside the VPN"));
        // The local address stays out of the copyable report.
        assert!(!outside.message.contains("192.168"));
        for route in [Some(tunnel), None] {
            let missing = result(None, route);
            assert_eq!(missing.level, DiagnosticLevel::Fail);
            assert!(missing.message.contains("didn't reach your VPS"));
        }
    }

    #[test]
    fn untunneled_ipv6_fails_only_when_it_can_leave_unblocked() {
        let route = Some("2001:db8:1::5".parse().unwrap());
        assert_eq!(
            untunneled_ipv6(None, false).level,
            DiagnosticLevel::NotApplicable
        );
        assert_eq!(
            untunneled_ipv6(route, true).level,
            DiagnosticLevel::NotApplicable
        );
        let leak = untunneled_ipv6(route, false);
        assert_eq!(leak.level, DiagnosticLevel::Fail);
        assert_eq!(leak.code, "leak_ipv6");
    }

    #[test]
    fn selected_routing_skips_what_it_leaves_outside_by_design() {
        let mut state = current();
        assert!(selected_only(&state, "IPv4").is_none());
        state.split_routes = true;
        assert!(selected_only(&state, "IPv4").is_some());
        assert!(selected_only(&state, "IPv6").is_some());
        // System DNS still uses the VPS with selected subnets.
        assert!(selected_only(&state, "DNS").is_none());
        state.split_applications = true;
        assert!(selected_only(&state, "DNS").is_some());
    }

    #[test]
    fn dns_passes_only_with_the_vps_resolver_answer() {
        let server: IpAddr = "10.77.0.1".parse().unwrap();
        assert_eq!(dns_result(&[server], server).level, DiagnosticLevel::Pass);
        for answers in [vec![], vec!["192.0.2.10".parse().unwrap()]] {
            assert_eq!(dns_result(&answers, server).level, DiagnosticLevel::Fail);
        }
        assert!(route_source(IpAddr::V4(Ipv4Addr::LOCALHOST)).is_some());
    }
}
