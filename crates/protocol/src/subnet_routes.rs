//! Owner-assigned LAN ranges that one device forwards for the peers allowed to reach it.

use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;

/// Across the whole server, so every consuming device's route list stays small.
pub const MAX_SUBNET_ROUTES: usize = 16;

/// What the VPS forwards for one device right now, as status reports it to that device.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct DeviceSubnetRoutes {
    /// LAN ranges the VPS sends to this device, which forwards them to its network.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub announced: Vec<String>,
    /// Other devices' LAN ranges this device may reach through the VPS.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reachable: Vec<String>,
}

impl DeviceSubnetRoutes {
    pub fn is_empty(&self) -> bool {
        self.announced.is_empty() && self.reachable.is_empty()
    }
}

impl crate::ServerProfile {
    /// Adopts the caller's authority and routes from an authorized status; true if any changed.
    pub fn adopt_caller_status(&mut self, status: &crate::ServerStatus) -> bool {
        let Some(role) = status.caller_role else {
            return false;
        };
        let before = (
            self.role,
            self.administrator,
            self.device_id,
            self.subnet_routes.clone(),
        );
        self.role = role;
        self.administrator = status.caller_administrator;
        if status.caller_device_id.is_some() {
            self.device_id = status.caller_device_id;
        }
        self.subnet_routes = status.caller_subnet_routes.clone();
        before
            != (
                self.role,
                self.administrator,
                self.device_id,
                self.subnet_routes.clone(),
            )
    }
}

const PRIVATE_BLOCKS: [(Ipv4Addr, u8); 3] = [
    (Ipv4Addr::new(10, 0, 0, 0), 8),
    (Ipv4Addr::new(172, 16, 0, 0), 12),
    (Ipv4Addr::new(192, 168, 0, 0), 16),
];
/// The tunnel (10.77.0.0/24, bootstrap included) and measurement probes (10.77.1.0/24).
/// The private IPv6 tunnel prefix cannot overlap: subnet routes are IPv4 only.
const RESERVED: (Ipv4Addr, u8) = (Ipv4Addr::new(10, 77, 0, 0), 23);

fn mask(prefix: u8) -> u32 {
    u32::MAX.checked_shl(32 - u32::from(prefix)).unwrap_or(0)
}

fn overlaps(left: (Ipv4Addr, u8), right: (Ipv4Addr, u8)) -> bool {
    let mask = mask(left.1.min(right.1));
    u32::from(left.0) & mask == u32::from(right.0) & mask
}

/// Parses a canonical RFC 1918 IPv4 CIDR such as `192.168.1.0/24`.
pub fn parse_subnet_route(route: &str) -> Result<(Ipv4Addr, u8), String> {
    let invalid = || format!("{route:?} is not an IPv4 CIDR such as 192.168.1.0/24");
    let (address, prefix) = route.split_once('/').ok_or_else(invalid)?;
    let address: Ipv4Addr = address.parse().map_err(|_| invalid())?;
    let prefix = prefix
        .parse::<u8>()
        .ok()
        .filter(|prefix| *prefix <= 32)
        .ok_or_else(invalid)?;
    let network = Ipv4Addr::from(u32::from(address) & mask(prefix));
    if format!("{network}/{prefix}") != route {
        return Err(format!("write {route:?} as {network}/{prefix}"));
    }
    if !PRIVATE_BLOCKS
        .iter()
        .any(|block| prefix >= block.1 && overlaps((network, prefix), *block))
    {
        return Err(format!(
            "{route} must be inside 10.0.0.0/8, 172.16.0.0/12 or 192.168.0.0/16"
        ));
    }
    if overlaps((network, prefix), RESERVED) {
        return Err(format!(
            "{route} overlaps the SirinVPN tunnel addresses 10.77.0.0/23"
        ));
    }
    Ok((network, prefix))
}

/// The first route that overlaps `existing`, an IPv4 destination as `ip route` prints it
/// (`10.0.0.0/8`, or `10.1.2.3` for a host); `None` for anything else.
pub fn overlapping_subnet_route<'a>(existing: &str, routes: &'a [String]) -> Option<&'a str> {
    let (address, prefix) = existing.split_once('/').unwrap_or((existing, "32"));
    let existing = (
        address.parse().ok()?,
        prefix.parse().ok().filter(|prefix| *prefix <= 32)?,
    );
    routes
        .iter()
        .find(|route| parse_subnet_route(route).is_ok_and(|route| overlaps(route, existing)))
        .map(String::as_str)
}

/// Every route of a server: canonical, private, bounded and without overlaps.
pub fn validate_subnet_routes<'a>(routes: impl IntoIterator<Item = &'a str>) -> Result<(), String> {
    let mut parsed = Vec::new();
    for route in routes {
        let network = parse_subnet_route(route)?;
        if parsed.iter().any(|existing| overlaps(*existing, network)) {
            return Err(format!("{route} overlaps another subnet route"));
        }
        parsed.push(network);
        if parsed.len() > MAX_SUBNET_ROUTES {
            return Err(format!(
                "a server can have at most {MAX_SUBNET_ROUTES} subnet routes"
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_canonical_private_routes_outside_the_tunnel_are_accepted() {
        for route in [
            "192.168.1.0/24",
            "192.168.0.0/16",
            "172.16.0.0/12",
            "10.0.0.0/16",
            "10.78.0.0/16",
            "10.76.255.0/24",
            "192.168.1.7/32",
        ] {
            assert!(parse_subnet_route(route).is_ok(), "{route}");
        }
        for route in [
            "0.0.0.0/0",
            "192.168.0.0/15",
            "172.0.0.0/8",
            "8.8.8.0/24",
            "100.64.0.0/10",
            "10.0.0.0/8",
            "10.77.0.0/24",
            "10.77.1.0/24",
            "10.77.0.0/16",
            "10.77.1.128/25",
            "192.168.1.1/24",
            "192.168.1.0/33",
            "192.168.1.0/024",
            "192.168.1.0/+24",
            "192.168.1.0",
            " 192.168.1.0/24",
            "fd00::/8",
            "192.168.001.0/24",
        ] {
            assert!(parse_subnet_route(route).is_err(), "{route}");
        }
        assert_eq!(
            parse_subnet_route("192.168.1.9/24").unwrap_err(),
            "write \"192.168.1.9/24\" as 192.168.1.0/24"
        );
    }

    #[test]
    fn routes_must_not_overlap_and_are_bounded() {
        assert!(validate_subnet_routes(["192.168.1.0/24", "192.168.2.0/24"]).is_ok());
        for overlap in [
            ["192.168.1.0/24", "192.168.1.0/24"],
            ["192.168.0.0/16", "192.168.1.0/24"],
            ["192.168.1.128/25", "192.168.1.0/24"],
        ] {
            assert!(validate_subnet_routes(overlap).is_err(), "{overlap:?}");
        }
        let routes: Vec<_> = (0..=MAX_SUBNET_ROUTES)
            .map(|index| format!("192.168.{index}.0/24"))
            .collect();
        assert!(
            validate_subnet_routes(routes[..MAX_SUBNET_ROUTES].iter().map(String::as_str)).is_ok()
        );
        assert!(validate_subnet_routes(routes.iter().map(String::as_str)).is_err());
    }

    #[test]
    fn existing_host_routes_are_matched_by_overlap() {
        let routes = ["192.168.1.0/24".to_owned(), "10.1.0.0/16".to_owned()];
        assert_eq!(
            overlapping_subnet_route("10.0.0.0/8", &routes),
            Some("10.1.0.0/16")
        );
        assert_eq!(
            overlapping_subnet_route("192.168.1.9", &routes),
            Some("192.168.1.0/24")
        );
        assert_eq!(overlapping_subnet_route("192.168.2.0/24", &routes), None);
        assert_eq!(overlapping_subnet_route("fd00::/8", &routes), None);
        assert_eq!(overlapping_subnet_route("default", &routes), None);
    }
}
