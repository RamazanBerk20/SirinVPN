use ipnet::IpNet;
#[cfg(target_os = "android")]
use sirinvpn_protocol::ServerProfile;
#[cfg(target_os = "android")]
use sirinvpn_tunnel_model::{ConnectionPreferences, TunnelRoutingMode};

/// Subtract private LAN ranges, retaining exact routes to the private VPS DNS.
/// Android 10 has no excludeRoute API, so emit the minimal CIDR complement.
#[cfg(target_os = "android")]
pub fn routes(
    profile: &ServerProfile,
    prefs: &ConnectionPreferences,
) -> anyhow::Result<Vec<IpNet>> {
    let mut routes: Vec<IpNet> = if prefs.routing.mode == TunnelRoutingMode::SelectedRoutes {
        prefs
            .routing
            .included_routes
            .iter()
            .map(|r| r.parse())
            .collect::<Result<_, _>>()?
    } else {
        vec!["0.0.0.0/0".parse()?, "::/0".parse()?]
    };
    if prefs.routing.allow_lan {
        for excluded in [
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.0.0/16",
            "169.254.0.0/16",
            "224.0.0.0/4",
            "fc00::/7",
            "fe80::/10",
            "ff00::/8",
        ] {
            let excluded = excluded.parse()?;
            routes = routes
                .into_iter()
                .flat_map(|route| subtract(route, excluded))
                .collect();
        }
    }
    routes.push(format!("{}/32", profile.server_tunnel_address).parse()?);
    if profile.ipv6_tunnel_enabled {
        routes.push(format!("{}/128", ipv6(profile.id, profile.server_tunnel_address)?).parse()?);
    }
    Ok(IpNet::aggregate(&routes))
}

fn subtract(route: IpNet, excluded: IpNet) -> Vec<IpNet> {
    if excluded.contains(&route) {
        return Vec::new();
    }
    if !route.contains(&excluded) {
        return vec![route];
    }
    let children = route
        .subnets(route.prefix_len() + 1)
        .expect("a containing route can split");
    children
        .flat_map(|child| subtract(child, excluded))
        .collect()
}

#[cfg(target_os = "android")]
pub fn ipv6(
    id: sirinvpn_protocol::ServerId,
    address: std::net::IpAddr,
) -> anyhow::Result<std::net::Ipv6Addr> {
    let std::net::IpAddr::V4(address) = address else {
        anyhow::bail!("Expected a private IPv4 address");
    };
    sirinvpn_protocol::ipv6_tunnel_address(id, address)
        .ok_or_else(|| anyhow::anyhow!("Invalid tunnel address"))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn subtraction_preserves_public_routes_and_never_excludes_the_other_family() {
        let routes = subtract("0.0.0.0/0".parse().unwrap(), "10.0.0.0/8".parse().unwrap());
        assert!(
            !routes
                .iter()
                .any(|r| r.contains(&"10.9.1.1".parse::<std::net::IpAddr>().unwrap()))
        );
        assert!(
            routes
                .iter()
                .any(|r| r.contains(&"192.0.2.9".parse::<std::net::IpAddr>().unwrap()))
        );
        assert_eq!(
            subtract("::/0".parse().unwrap(), "10.0.0.0/8".parse().unwrap()),
            vec!["::/0".parse::<IpNet>().unwrap()]
        );
    }
}
