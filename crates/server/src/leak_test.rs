//! On-demand leak test. The VPS reports only the source address of the request that asked and
//! keeps no per-check state: nothing is stored, counted or logged.
use super::*;
use sirinvpn_protocol::{LEAK_TEST_IPV4, LEAK_TEST_IPV6, LeakTestObservation};

/// Written by the installer; Unbound answers the leak-test DNS zone while it exists.
pub(super) const ZONE_FILE: &str = "/etc/unbound/unbound.conf.d/sirinvpn-leak-test.conf";

/// The TCP peer address of the current management connection.
#[derive(Clone, Copy)]
pub(super) struct PeerAddress(pub(super) IpAddr);

pub(super) async fn observe_handler(
    State(state): State<AppState>,
    Extension(caller): Extension<CallerIdentity>,
    Extension(PeerAddress(source_address)): Extension<PeerAddress>,
) -> Result<Json<ApiEnvelope<LeakTestObservation>>, ApiError> {
    authorize_device(&state, &caller, false).await?;
    Ok(Json(ApiEnvelope::new(LeakTestObservation {
        source_address,
    })))
}

/// Redirects the leak-test addresses to the private management listeners, but only when they
/// arrive through the tunnel; sent anywhere else they are dropped as documentation addresses.
/// The chains share the runtime measurement table, so its existing teardown removes them.
pub(super) fn rules(
    interface: &str,
    server: IpAddr,
    server_ipv6: Option<Ipv6Addr>,
    port: u16,
) -> String {
    let mut rules = format!(
        concat!(
            "add table inet sirinvpn_measurement\n",
            "add chain inet sirinvpn_measurement leak_test_prerouting {{ type nat hook prerouting priority dstnat; policy accept; }}\n",
            "add chain inet sirinvpn_measurement leak_test_input {{ type filter hook input priority -32; policy accept; }}\n",
            "flush chain inet sirinvpn_measurement leak_test_prerouting\nflush chain inet sirinvpn_measurement leak_test_input\n",
            "add rule inet sirinvpn_measurement leak_test_prerouting iifname \"{interface}\" ip daddr {ipv4} tcp dport {port} dnat ip to {server}:{port}\n",
        ),
        interface = interface,
        ipv4 = LEAK_TEST_IPV4,
        server = server,
        port = port,
    );
    if let Some(server_ipv6) = server_ipv6 {
        rules.push_str(&format!(
            concat!(
                "add rule inet sirinvpn_measurement leak_test_prerouting iifname \"{interface}\" ip6 daddr {ipv6} tcp dport {port} dnat ip6 to [{server_ipv6}]:{port}\n",
                // Like 10.77.0.1:8443, the private IPv6 listener only answers the tunnel.
                "add rule inet sirinvpn_measurement leak_test_input iifname != \"{interface}\" ip6 daddr {server_ipv6} tcp dport {port} drop\n",
            ),
            interface = interface,
            ipv6 = LEAK_TEST_IPV6,
            server_ipv6 = server_ipv6,
            port = port,
        ));
    }
    rules
}

pub(super) async fn install(
    configuration: &ServerConfiguration,
    server_ipv6: Option<Ipv6Addr>,
) -> Result<()> {
    apply_nft_batch(
        &rules(
            &configuration.interface_name,
            configuration.server_tunnel_address,
            server_ipv6,
            configuration.management_port,
        ),
        "leak-test redirection",
    )
    .await
}

#[cfg(test)]
mod tests;
