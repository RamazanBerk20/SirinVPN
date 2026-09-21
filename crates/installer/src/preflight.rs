//! Current VPS networking facts, collected only over the pinned SSH connection.
use super::*;
use sirinvpn_protocol::PortForwardProtocol;
mod inspection;
use inspection::*;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct NetworkPreflight {
    pub public_endpoint: String,
    pub endpoint_addresses: Vec<IpAddr>,
    pub ssh_local_address: Option<IpAddr>,
    pub exposure: AddressExposure,
    pub assigned_addresses: Vec<AssignedAddress>,
    pub required_ports: Vec<RequiredPort>,
    pub issues: Vec<NetworkIssue>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AddressExposure {
    PublicInterface,
    NatOrProxy,
    PrivateEndpoint,
    Unresolved,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AssignedAddress {
    pub interface: String,
    pub address: IpAddr,
    pub prefix_length: u8,
    pub public: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct RequiredPort {
    pub protocol: PortForwardProtocol,
    pub port: u16,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct NetworkIssue {
    pub blocking: bool,
    pub code: &'static str,
    pub message: String,
}

impl NetworkPreflight {
    pub fn can_install(&self) -> bool {
        self.issues.iter().all(|issue| !issue.blocking)
    }

    fn issue(&mut self, blocking: bool, code: &'static str, message: String) {
        if !self
            .issues
            .iter()
            .any(|issue| issue.code == code && issue.message == message)
        {
            self.issues.push(NetworkIssue {
                blocking,
                code,
                message,
            });
        }
    }

    pub(super) fn require_compatible(&self) -> Result<(), InstallerError> {
        if self.can_install() {
            return Ok(());
        }
        Err(InstallerError::Incompatible(
            self.issues
                .iter()
                .filter(|issue| issue.blocking)
                .map(|issue| issue.message.as_str())
                .collect::<Vec<_>>()
                .join(" "),
        ))
    }
}

pub(super) fn inspect_network(
    session: &Session,
    target: &SshTarget,
    discovery: &ServerDiscovery,
    transport: &TransportSetup,
    discovery_port: Option<u16>,
) -> Result<NetworkPreflight, InstallerError> {
    transport.validate()?;
    let public_endpoint = transport.public_host.as_deref().unwrap_or(&target.host);
    let endpoint_addresses = (public_endpoint, 0)
        .to_socket_addrs()
        .map(|addresses| {
            let mut result = Vec::new();
            for address in addresses.take(16) {
                if !result.contains(&address.ip()) && result.len() < 4 {
                    result.push(address.ip());
                }
            }
            result
        })
        .unwrap_or_default();
    let ports = required_ports(transport, discovery_port);
    let output = run_privileged(session, target, &inspection_command(&ports))
        .map_err(|error| phase_error("network preflight", error))?;
    analyze(
        discovery,
        public_endpoint,
        endpoint_addresses,
        ports,
        &output,
    )
    .map_err(|error| phase_error("network preflight", error))
}

fn required_ports(transport: &TransportSetup, discovery_port: Option<u16>) -> Vec<RequiredPort> {
    let mut ports = vec![
        RequiredPort {
            protocol: PortForwardProtocol::Udp,
            port: transport.wireguard_port,
        },
        RequiredPort {
            protocol: PortForwardProtocol::Udp,
            port: transport.obfuscated_udp_port,
        },
        RequiredPort {
            protocol: PortForwardProtocol::Tcp,
            port: transport.tcp_tls_port,
        },
    ];
    if let Some(port) = discovery_port.filter(|port| *port != transport.tcp_tls_port) {
        ports.push(RequiredPort {
            protocol: PortForwardProtocol::Tcp,
            port,
        });
    }
    ports
}

fn public_address(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => {
            let [a, b, c, _] = address.octets();
            !address.is_private()
                && !address.is_loopback()
                && !address.is_link_local()
                && a != 0
                && a < 224
                && !(a == 100 && (64..=127).contains(&b))
                && !(a == 192 && b == 0 && (c == 0 || c == 2))
                && !(a == 198 && (b == 18 || b == 19 || (b == 51 && c == 100)))
                && !(a == 203 && b == 0 && c == 113)
        }
        IpAddr::V6(address) => {
            let s = address.segments();
            s[0] & 0xe000 == 0x2000 && !(s[0] == 0x2001 && s[1] == 0xdb8)
        }
    }
}

fn valid_interface(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 15
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.:-".contains(&b))
}

fn field<'a>(value: &'a serde_json::Value, name: &str) -> Option<&'a str> {
    value.get(name).and_then(serde_json::Value::as_str)
}

fn analyze(
    discovery: &ServerDiscovery,
    endpoint: &str,
    endpoint_addresses: Vec<IpAddr>,
    required_ports: Vec<RequiredPort>,
    output: &str,
) -> anyhow::Result<NetworkPreflight> {
    let sections = sections(output)?;
    let assigned: serde_json::Value = serde_json::from_str(sections["addresses"])?;
    let mut report = NetworkPreflight {
        public_endpoint: endpoint.into(),
        endpoint_addresses,
        ssh_local_address: sections["ssh"].trim().parse().ok(),
        exposure: AddressExposure::Unresolved,
        assigned_addresses: Vec::new(),
        required_ports,
        issues: Vec::new(),
    };
    for interface in assigned
        .as_array()
        .ok_or_else(|| anyhow!("invalid interface addresses"))?
    {
        let name = field(interface, "ifname")
            .filter(|name| valid_interface(name))
            .ok_or_else(|| anyhow!("invalid interface name"))?;
        for entry in interface
            .get("addr_info")
            .and_then(serde_json::Value::as_array)
            .into_iter()
            .flatten()
        {
            let Some(address) = field(entry, "local").and_then(|text| text.parse::<IpAddr>().ok())
            else {
                continue;
            };
            let prefix = entry
                .get("prefixlen")
                .and_then(serde_json::Value::as_u64)
                .filter(|bits| *bits <= if address.is_ipv4() { 32 } else { 128 })
                .ok_or_else(|| anyhow!("invalid interface prefix"))? as u8;
            if address.is_loopback() {
                continue;
            }
            report.assigned_addresses.push(AssignedAddress {
                interface: name.into(),
                address,
                prefix_length: prefix,
                public: public_address(address),
            });
            if report.assigned_addresses.len() > 256 {
                bail!("too many assigned VPS addresses");
            }
            if name == INTERFACE_NAME && discovery.sirinvpn_installed {
                continue;
            }
            if let IpAddr::V4(address) = address
                && address.octets()[..3] == [10, 77, 0]
            {
                report.issue(true, "tunnel_address_conflict", format!("Interface {name} already uses {address}, inside SirinVPN's 10.77.0.0/24 network. Move the conflicting network before installing."));
            }
        }
    }
    report.exposure = if report.endpoint_addresses.is_empty() {
        AddressExposure::Unresolved
    } else if !report
        .endpoint_addresses
        .iter()
        .any(|address| public_address(*address))
    {
        AddressExposure::PrivateEndpoint
    } else if report.endpoint_addresses.iter().any(|address| {
        report
            .assigned_addresses
            .iter()
            .any(|assigned| assigned.address == *address && assigned.public)
    }) {
        AddressExposure::PublicInterface
    } else {
        AddressExposure::NatOrProxy
    };
    match report.exposure {
        AddressExposure::Unresolved => report.issue(true, "endpoint_resolution", "The public VPN address does not resolve from this device. Correct it before installation.".into()),
        AddressExposure::NatOrProxy => report.issue(false, "nat_or_proxy", "The public VPN address is not assigned to a VPS interface. A provider NAT mapping or proxy may be involved. Forward the listed UDP/TCP ports to this VPS with the same external and internal port numbers; SSH access alone does not establish VPN reachability.".into()),
        AddressExposure::PrivateEndpoint => report.issue(false, "private_endpoint", "The VPN address is private or local. It will work only from networks that can route to it. Set a public VPN address for access from the Internet.".into()),
        AddressExposure::PublicInterface => {}
    }
    check_listeners(
        discovery,
        &mut report,
        sections["listeners"],
        sections["wireguard"],
    )?;
    check_routes(discovery, &mut report, sections["routes"])?;
    check_firewalls_and_links(discovery, &mut report, &sections)?;
    Ok(report)
}

fn check_listeners(
    discovery: &ServerDiscovery,
    report: &mut NetworkPreflight,
    listeners: &str,
    wireguard: &str,
) -> anyhow::Result<()> {
    let own_wg_ports = wireguard
        .lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            (fields.next()? == INTERFACE_NAME && discovery.sirinvpn_installed)
                .then(|| fields.next()?.parse::<u16>().ok())
                .flatten()
        })
        .collect::<Vec<_>>();
    for line in listeners.lines() {
        let fields = line.split_whitespace().collect::<Vec<_>>();
        if fields.len() < 5 {
            bail!("invalid listener inspection");
        }
        let Some((address, port)) = fields[4].rsplit_once(':') else {
            bail!("invalid listener inspection");
        };
        let address = address.trim_matches(['[', ']']);
        let port = port
            .parse::<u16>()
            .map_err(|_| anyhow!("invalid listener port"))?;
        let wildcard_or_vpn = ["*", "0.0.0.0", "::", SERVER_TUNNEL_ADDRESS].contains(&address);
        let conflict = match port {
            53 => {
                (wildcard_or_vpn || address == "127.0.0.1")
                    && !(discovery.unbound_installed && line.contains("(\"unbound\",pid="))
            }
            8443 => {
                fields[0] == "tcp"
                    && wildcard_or_vpn
                    && !(discovery.sirinvpn_installed && line.contains("(\"sirinvpn-server\",pid="))
            }
            _ => false,
        };
        if conflict {
            report.issue(true, "private_service_port", format!("Port {port} is already bound on an address needed by SirinVPN's private {}. Reconfigure the conflicting service before installing.", if port == 53 { "DNS resolver" } else { "management API" }));
        }
    }
    for requested in report.required_ports.clone() {
        if requested.protocol == PortForwardProtocol::Tcp
            && requested.port == discovery.ssh_server_port
        {
            report.issue(
                true,
                "ssh_port_conflict",
                format!(
                    "TCP port {} is used by SSH. Choose a different TCP/TLS port.",
                    requested.port
                ),
            );
        }
        for line in listeners.lines() {
            let fields = line.split_whitespace().collect::<Vec<_>>();
            if fields.len() < 5 {
                bail!("invalid listener inspection");
            }
            let protocol = match fields[0] {
                "tcp" => PortForwardProtocol::Tcp,
                "udp" => PortForwardProtocol::Udp,
                _ => continue,
            };
            let port = fields[4]
                .rsplit_once(':')
                .and_then(|(_, port)| port.parse::<u16>().ok())
                .ok_or_else(|| anyhow!("invalid listener port"))?;
            if port != requested.port || protocol != requested.protocol {
                continue;
            }
            let owned = discovery.sirinvpn_installed
                && (line.contains("(\"sirinvpn-server\",pid=")
                    || (protocol == PortForwardProtocol::Udp
                        && own_wg_ports.contains(&port)
                        && !line.contains("users:")));
            if !owned {
                report.issue(true, "port_in_use", format!("{} port {port} is already listening for another service. Choose a free transport port or reconfigure that service.", match protocol { PortForwardProtocol::Tcp => "TCP", PortForwardProtocol::Udp => "UDP" }));
            }
        }
    }
    Ok(())
}

fn check_routes(
    discovery: &ServerDiscovery,
    report: &mut NetworkPreflight,
    routes: &str,
) -> anyhow::Result<()> {
    let routes: serde_json::Value = serde_json::from_str(routes)?;
    for route in routes.as_array().ok_or_else(|| anyhow!("invalid routes"))? {
        let Some(destination) = field(route, "dst").filter(|destination| *destination != "default")
        else {
            continue;
        };
        let (address, prefix) = destination.split_once('/').unwrap_or((destination, "32"));
        let (Ok(address), Ok(prefix)) = (address.parse::<Ipv4Addr>(), prefix.parse::<u32>()) else {
            continue;
        };
        if prefix == 0 || prefix > 32 {
            continue;
        }
        let mask = u32::MAX << (32 - prefix.min(24));
        if u32::from(address) & mask != u32::from(Ipv4Addr::new(10, 77, 0, 0)) & mask {
            continue;
        }
        let interface = field(route, "dev").unwrap_or("unknown");
        if interface == INTERFACE_NAME && discovery.sirinvpn_installed {
            continue;
        }
        if !valid_interface(interface) {
            bail!("invalid route interface");
        }
        report.issue(prefix >= 24, "tunnel_route_conflict", format!("Route {destination} on {interface} overlaps SirinVPN's 10.77.0.0/24 network. Check the existing private/VPN network before installing."));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
