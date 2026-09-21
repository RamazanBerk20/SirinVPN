//! Routing.

use super::*;
pub(super) use sirinvpn_tunnel_model::validate_request;

pub(super) fn kill_switch_firewall(
    request: &TunnelConnectRequest,
    endpoint: IpAddr,
    replace: bool,
) -> String {
    let replace_existing = if replace {
        "flush chain inet sirinvpn_guard output\n"
    } else {
        ""
    };
    let endpoint_family = if endpoint.is_ipv6() { "ip6" } else { "ip" };
    let network_rule = match request.transport {
        TransportKind::TcpFallback | TransportKind::TlsLike => {
            format!(
                "meta mark 0xca6c {endpoint_family} daddr {endpoint} tcp dport {} accept",
                request.endpoint_port
            )
        }
        TransportKind::DirectUdp | TransportKind::ObfuscatedUdp => {
            format!(
                "meta mark 0xca6c {endpoint_family} daddr {endpoint} udp dport {} accept",
                request.endpoint_port
            )
        }
    };
    let mut protected_rules = String::new();
    if request.routing.mode != TunnelRoutingMode::SelectedApplications
        && (request.routing.mode == TunnelRoutingMode::SelectedRoutes || request.routing.allow_lan)
    {
        protected_rules.push_str(&format!(
            "    ip daddr {} drop\n    udp dport {{ 53, 853 }} drop\n    tcp dport {{ 53, 853 }} drop\n",
            request.dns_address
        ));
    }
    if request.routing.allow_lan && request.routing.mode != TunnelRoutingMode::SelectedApplications
    {
        for route in IPV4_LAN_ROUTES {
            protected_rules.push_str(&format!("    ip daddr {route} accept\n"));
        }
        for route in IPV6_LAN_ROUTES {
            protected_rules.push_str(&format!("    ip6 daddr {route} accept\n"));
        }
    }
    if request.routing.mode == TunnelRoutingMode::SelectedRoutes {
        for route in parsed_included_routes(&request.routing) {
            let family = if matches!(route, IpNet::V4(_)) {
                "ip"
            } else {
                "ip6"
            };
            protected_rules.push_str(&format!(
                "    {family} daddr {route} oifname != \"{INTERFACE_NAME}\" drop\n"
            ));
        }
    }
    let policy = if request.routing.mode == TunnelRoutingMode::FullTunnel {
        "drop"
    } else {
        "accept"
    };
    format!(
        r#"{replace_existing}table inet sirinvpn_guard {{
  chain output {{
    type filter hook output priority filter; policy {policy};
    oifname "lo" accept
    oifname "{INTERFACE_NAME}" accept
    {network_rule}
    udp sport 68 udp dport 67 accept
{protected_rules}  }}
}}
"#,
    )
}

pub(super) fn parsed_included_routes(
    routing: &TunnelRoutingPolicy,
) -> impl Iterator<Item = IpNet> + '_ {
    routing
        .included_routes
        .iter()
        .map(|route| route.parse::<IpNet>().expect("validated routing policy"))
}

pub(super) fn routing_uses_ipv6(routing: &TunnelRoutingPolicy) -> bool {
    match routing.mode {
        TunnelRoutingMode::FullTunnel | TunnelRoutingMode::SelectedApplications => true,
        TunnelRoutingMode::SelectedRoutes => {
            parsed_included_routes(routing).any(|route| matches!(route, IpNet::V6(_)))
        }
    }
}

pub(super) fn routing_family_destinations(
    routing: &TunnelRoutingPolicy,
    ipv6: bool,
) -> Vec<String> {
    if routing.mode != TunnelRoutingMode::SelectedRoutes {
        return vec!["default".to_owned()];
    }
    parsed_included_routes(routing)
        .filter(|route| matches!(route, IpNet::V6(_)) == ipv6)
        .map(|route| route.to_string())
        .collect()
}

pub(super) fn wireguard_allowed_ips(request: &TunnelConnectRequest) -> String {
    if request.routing.mode != TunnelRoutingMode::SelectedRoutes {
        return if request.client_ipv6_address.is_some() {
            "0.0.0.0/0,::/0".to_owned()
        } else {
            "0.0.0.0/0".to_owned()
        };
    }
    let mut routes = request
        .routing
        .included_routes
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    routes.insert(format!("{}/32", request.dns_address));
    routes.into_iter().collect::<Vec<_>>().join(",")
}

pub(super) fn route_table_destinations(
    request: &TunnelConnectRequest,
    family: &str,
) -> Vec<String> {
    let ipv6 = family == "-6";
    let mut routes = routing_family_destinations(&request.routing, ipv6)
        .into_iter()
        .collect::<BTreeSet<_>>();
    if !ipv6 && request.routing.mode == TunnelRoutingMode::SelectedRoutes {
        routes.insert(format!("{}/32", request.dns_address));
    }
    routes.into_iter().collect()
}

pub(super) fn transient_ipv6_firewall(
    allow_lan: bool,
    request: &TunnelConnectRequest,
    endpoint: IpAddr,
) -> String {
    let mut endpoint_rules = String::new();
    if endpoint.is_ipv6() {
        let protocol = if matches!(
            request.transport,
            TransportKind::TlsLike | TransportKind::TcpFallback
        ) {
            "tcp"
        } else {
            "udp"
        };
        endpoint_rules.push_str(&format!(
            "    meta mark 0xca6c ip6 daddr {endpoint} {protocol} dport {} accept\n",
            request.endpoint_port
        ));
        if let Some(port) = request.endpoint_identity.as_ref().and_then(|identity| {
            identity
                .descriptor
                .endpoint_discovery_port
                .or_else(|| identity.descriptor.tls_like.as_ref().map(|tls| tls.port))
        }) {
            endpoint_rules.push_str(&format!(
                "    meta mark 0xca6c ip6 daddr {endpoint} tcp dport {port} accept\n"
            ));
        }
    }
    for server in request
        .endpoint_dns_servers
        .iter()
        .filter(|server| server.is_ipv6())
    {
        endpoint_rules.push_str(&format!("    meta mark 0xca6c ip6 daddr {} udp dport 53 accept\n    meta mark 0xca6c ip6 daddr {} tcp dport 53 accept\n", server.ip(), server.ip()));
    }
    if endpoint.is_ipv6() || request.endpoint_dns_servers.iter().any(SocketAddr::is_ipv6) {
        endpoint_rules.push_str("    ip6 hoplimit 255 icmpv6 type { nd-router-solicit, nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert } accept\n    ip6 daddr ff02::1:2 udp sport 546 udp dport 547 accept\n");
    }
    let lan_rules = if allow_lan {
        IPV6_LAN_ROUTES
            .iter()
            .map(|route| format!("    ip6 daddr {route} accept\n"))
            .collect::<String>()
    } else {
        String::new()
    };
    format!(
        r#"table ip6 sirinvpn_client6 {{
  chain output {{
    type filter hook output priority filter; policy accept;
    oifname "lo" accept
{endpoint_rules}{lan_rules}    oifname != "lo" drop
  }}
}}
"#,
    )
}
