use crate::firewall_plan::{host, lan_routes};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use sirinvpn_tunnel_model::{TunnelConnectRequest, TunnelRoutingMode, validate_request};
use std::{collections::BTreeSet, net::IpAddr};

pub(crate) const OWNED_ROUTE_METRIC: u32 = 42867;
pub(crate) const APPLICATION_ROUTE_METRIC: u32 = 60000;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RouteRecord {
    pub tunnel: bool,
    pub interface_luid: u64,
    pub interface_index: u32,
    pub destination: String,
    pub next_hop: IpAddr,
    pub scope_id: u32,
    pub metric: u32,
}

impl RouteRecord {
    pub(crate) fn validate(&self) -> bool {
        self.interface_luid != 0
            && self.interface_index != 0
            && if self.tunnel {
                self.metric == 0
                    || self.metric == APPLICATION_ROUTE_METRIC && self.destination == "0.0.0.0/0"
            } else {
                self.metric == OWNED_ROUTE_METRIC
            }
            && self.destination.parse::<IpNet>().is_ok_and(|route| {
                route.trunc().to_string() == self.destination
                    && route.addr().is_ipv4() == self.next_hop.is_ipv4()
            })
    }
}

pub(crate) fn validate(request: &TunnelConnectRequest) -> Result<(), crate::ServiceError> {
    validate_request(request).map_err(|_| crate::ServiceError::InvalidRequest)?;
    let address = request.client_address.octets();
    if request.policy.is_none()
        || address[..3] != [10, 77, 0]
        || !(2..=254).contains(&address[3])
        || request.dns_address.octets() != [10, 77, 0, 1]
    {
        return Err(crate::ServiceError::InvalidRequest);
    }
    if request.routing.mode == TunnelRoutingMode::SelectedApplications
        && (!request.connection_policy().kill_switch || request.routing.allow_lan)
    {
        return Err(crate::ServiceError::ApplicationPolicyRequired);
    }
    Ok(())
}

pub(crate) fn allowed_ips(request: &TunnelConnectRequest) -> Vec<IpNet> {
    if request.routing.mode != TunnelRoutingMode::SelectedRoutes {
        let mut routes = vec!["0.0.0.0/0".parse().unwrap()];
        if request.client_ipv6_address.is_some()
            && request.routing.mode == TunnelRoutingMode::FullTunnel
        {
            routes.push("::/0".parse().unwrap());
        }
        routes
    } else {
        let mut routes: BTreeSet<IpNet> = request
            .routing
            .included_routes
            .iter()
            .filter_map(|route| route.parse().ok())
            .collect();
        routes.insert(host(request.dns_address.into()));
        routes.into_iter().collect()
    }
}

pub(crate) fn tunnel_routes(request: &TunnelConnectRequest) -> Vec<IpNet> {
    let mut routes: BTreeSet<IpNet> = if request.routing.mode == TunnelRoutingMode::FullTunnel {
        // More specific than default routes. Endpoint host routes stay outside.
        let mut routes = vec!["0.0.0.0/1".parse().unwrap(), "128.0.0.0/1".parse().unwrap()];
        if request.client_ipv6_address.is_some() {
            routes.extend([
                "::/1".parse::<IpNet>().unwrap(),
                "8000::/1".parse::<IpNet>().unwrap(),
            ]);
        }
        routes.into_iter().collect()
    } else {
        allowed_ips(request).into_iter().collect()
    };
    if request.routing.allow_lan {
        for excluded in lan_routes() {
            routes = routes
                .into_iter()
                .flat_map(|route| exclude(route, excluded))
                .collect();
        }
    }
    // Private management and DNS never fall through a LAN exception.
    routes.insert(host(request.dns_address.into()));
    routes.into_iter().collect()
}

fn exclude(route: IpNet, excluded: IpNet) -> Vec<IpNet> {
    if route.addr().is_ipv4() != excluded.addr().is_ipv4() {
        return vec![route];
    }
    if excluded.contains(&route) {
        return Vec::new();
    }
    if !route.contains(&excluded) {
        return vec![route];
    }
    match route {
        IpNet::V4(route) => route
            .subnets(route.prefix_len() + 1)
            .expect("non-host parent")
            .flat_map(|child| exclude(child.into(), excluded))
            .collect(),
        IpNet::V6(route) => route
            .subnets(route.prefix_len() + 1)
            .expect("non-host parent")
            .flat_map(|child| exclude(child.into(), excluded))
            .collect(),
    }
}

pub(crate) fn usable_endpoint(address: IpAddr) -> bool {
    !matches!(address, IpAddr::V4(address) if address.is_broadcast())
        && !address.is_loopback()
        && !address.is_unspecified()
        && !address.is_multicast()
        && !"10.77.0.0/24".parse::<IpNet>().unwrap().contains(&address)
        && !matches!(address, IpAddr::V6(address) if address.is_unicast_link_local())
}
