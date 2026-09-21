//! The complete owned WFP policy, independent of native allocation and I/O.
use ipnet::IpNet;
use sirinvpn_protocol::TransportKind;
use sirinvpn_tunnel_model::{TunnelConnectRequest, TunnelRoutingMode};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Layer {
    ConnectV4,
    ReceiveV4,
    ConnectV6,
    ReceiveV6,
    BindV4,
}
impl Layer {
    pub(crate) const TRAFFIC: [Self; 4] = [
        Self::ConnectV4,
        Self::ReceiveV4,
        Self::ConnectV6,
        Self::ReceiveV6,
    ];
    pub(crate) const ALL: [Self; 5] = [
        Self::ConnectV4,
        Self::ReceiveV4,
        Self::ConnectV6,
        Self::ReceiveV6,
        Self::BindV4,
    ];
    pub(crate) fn ipv6(self) -> bool {
        matches!(self, Self::ConnectV6 | Self::ReceiveV6)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum Condition {
    ServiceApplication,
    SystemUser,
    Application(Vec<u8>),
    User(String),
    Interface(u64),
    Remote(IpNet),
    RemotePort(u16),
    LocalPort(u16),
    Protocol(u8),
    Loopback,
    IcmpType(u16),
    IcmpCode(u16),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Rule {
    pub layer: Layer,
    pub weight: u64,
    pub permit: bool,
    pub boot: bool,
    pub conditions: Vec<Condition>,
    pub bind_address: Option<Ipv4Addr>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct FirewallPlan {
    pub persistent: bool,
    pub rules: Vec<Rule>,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct ControlSocket {
    pub address: SocketAddr,
    pub protocol: u8,
    pub interface_luid: u64,
}

impl FirewallPlan {
    pub(crate) fn persistent_rules(&self) -> Vec<Rule> {
        if !self.persistent {
            return Vec::new();
        }
        self.rules
            .iter()
            .filter(|rule| !self.dynamic_permission(rule))
            .cloned()
            .collect()
    }
    pub(crate) fn dynamic_rules(&self) -> Vec<Rule> {
        self.rules
            .iter()
            .filter(|rule| !self.persistent || self.dynamic_permission(rule))
            .cloned()
            .collect()
    }
    fn dynamic_permission(&self, rule: &Rule) -> bool {
        rule.bind_address.is_some()
            || !rule.boot
                && rule.permit
                && rule.conditions.iter().any(|condition| {
                    matches!(
                        condition,
                        Condition::ServiceApplication | Condition::Interface(_)
                    )
                })
    }

    /// Temporary endpoint lookup/control exceptions belong only to this service
    /// and this underlay. They never become boot-time permits or general DNS rules.
    pub(crate) fn with_control(mut self, sockets: &[ControlSocket]) -> Self {
        use Condition::*;
        for socket in sockets {
            for layer in Layer::TRAFFIC
                .into_iter()
                .filter(|layer| layer.ipv6() == socket.address.is_ipv6())
            {
                self.add(
                    layer,
                    105,
                    true,
                    vec![
                        ServiceApplication,
                        SystemUser,
                        Interface(socket.interface_luid),
                        Remote(host(socket.address.ip())),
                        RemotePort(socket.address.port()),
                        Protocol(socket.protocol),
                    ],
                );
            }
        }
        self
    }

    pub(crate) fn for_tunnel(
        request: &TunnelConnectRequest,
        endpoints: &[SocketAddr],
        luid: Option<u64>,
    ) -> Self {
        use Condition::*;
        let persistent = request.connection_policy().kill_switch;
        let mut plan = Self {
            persistent,
            rules: Vec::new(),
        };
        for layer in Layer::TRAFFIC {
            // Local IPC and the loopback WireGuard-to-carrier hop stay usable.
            plan.add(layer, 110, true, vec![Loopback]);
            for endpoint in endpoints
                .iter()
                .filter(|endpoint| endpoint.is_ipv6() == layer.ipv6())
            {
                // Path plus SYSTEM token prevents the same installed executable
                // being run as an ordinary user to obtain an Internet exception.
                plan.add(
                    layer,
                    100,
                    true,
                    vec![
                        ServiceApplication,
                        SystemUser,
                        Remote(host(endpoint.ip())),
                        RemotePort(endpoint.port()),
                        Protocol(
                            if matches!(
                                request.transport,
                                TransportKind::DirectUdp | TransportKind::ObfuscatedUdp
                            ) {
                                17
                            } else {
                                6
                            },
                        ),
                    ],
                );
            }
            if let Some(luid) = luid {
                if !layer.ipv6() {
                    for protocol in [6, 17] {
                        plan.add(
                            layer,
                            95,
                            true,
                            vec![
                                Interface(luid),
                                Remote(host(request.dns_address.into())),
                                RemotePort(53),
                                Protocol(protocol),
                            ],
                        );
                    }
                }
                if !layer.ipv6() || request.client_ipv6_address.is_some() {
                    plan.add(layer, 60, true, vec![Interface(luid)]);
                }
            }
            // LAN and selected-route exceptions never expose ordinary DNS/DoT.
            // Inbound responses have the DNS port as their remote port too.
            for port in [53, 853] {
                for protocol in [6, 17] {
                    plan.add(layer, 90, false, vec![RemotePort(port), Protocol(protocol)]);
                }
            }
            if !layer.ipv6() {
                plan.add(
                    layer,
                    50,
                    false,
                    vec![Remote(host(request.dns_address.into()))],
                );
            }
            if request.routing.allow_lan {
                for network in lan_routes()
                    .into_iter()
                    .filter(|network| network.addr().is_ipv6() == layer.ipv6())
                {
                    plan.add(layer, 40, true, vec![Remote(network)]);
                }
            }
            let full = request.routing.mode == TunnelRoutingMode::FullTunnel;
            if full
                || layer.ipv6()
                    && request.client_ipv6_address.is_none()
                    && request.routing.mode != TunnelRoutingMode::SelectedApplications
            {
                plan.add(layer, 0, false, Vec::new());
            } else {
                let protected = request
                    .routing
                    .included_routes
                    .iter()
                    .filter_map(|value| value.parse::<IpNet>().ok())
                    .chain([host(request.dns_address.into())]);
                for route in protected.filter(|route| route.addr().is_ipv6() == layer.ipv6()) {
                    plan.add(layer, 10, false, vec![Remote(route)]);
                }
            }
        }
        plan.network_configuration();
        if persistent {
            // Boot protection admits no carrier or interface identified during a
            // previous boot. BFE atomically replaces it with the persistent policy.
            let mut boot: Vec<_> = plan
                .rules
                .iter()
                .filter(|rule| {
                    !rule.permit
                        || rule.weight == 40
                        || rule.conditions == [Loopback]
                        || rule.weight == 80
                })
                .cloned()
                .collect();
            for rule in &mut boot {
                rule.boot = true;
            }
            plan.rules.extend(boot);
        }
        plan
    }

    pub(crate) fn with_applications(
        mut self,
        applications: &[crate::application_plan::SelectedApplication],
        owner: &str,
        source: Ipv4Addr,
        luid: Option<u64>,
    ) -> Self {
        use Condition::*;
        for application in applications {
            let identity = vec![
                Application(application.app_id.clone()),
                User(owner.to_owned()),
            ];
            for layer in Layer::TRAFFIC {
                self.add(layer, 120, false, identity.clone());
                if self.persistent {
                    let mut boot = self.rules.last().unwrap().clone();
                    boot.boot = true;
                    self.rules.push(boot);
                }
                // Keep local IPC usable; it does not confer routing on a separate
                // executable handling a browser/service's network requests.
                let mut local = identity.clone();
                local.push(Loopback);
                self.add(layer, 140, true, local);
                if let Some(luid) = luid
                    && !layer.ipv6()
                {
                    for protocol in [6, 17] {
                        let mut permit = identity.clone();
                        permit.extend([Interface(luid), Protocol(protocol)]);
                        self.add(layer, 130, true, permit);
                    }
                }
            }
            if luid.is_some() {
                for protocol in [6, 17] {
                    let mut conditions = identity.clone();
                    conditions.push(Protocol(protocol));
                    self.add(Layer::BindV4, 100, true, conditions);
                    self.rules.last_mut().unwrap().bind_address = Some(source);
                }
            }
        }
        self
    }

    fn network_configuration(&mut self) {
        use Condition::*;
        // DHCP broadcast discovery and replies, scoped by both ports. Unicast
        // renewals can fall back to rebinding without opening arbitrary UDP hosts.
        self.add(
            Layer::ConnectV4,
            80,
            true,
            vec![
                Protocol(17),
                LocalPort(68),
                RemotePort(67),
                Remote("255.255.255.255/32".parse().unwrap()),
            ],
        );
        self.add(
            Layer::ReceiveV4,
            80,
            true,
            vec![Protocol(17), LocalPort(68), RemotePort(67)],
        );
        for destination in ["ff02::1:2/128", "ff05::1:3/128"] {
            self.add(
                Layer::ConnectV6,
                80,
                true,
                vec![
                    Protocol(17),
                    LocalPort(546),
                    RemotePort(547),
                    Remote(destination.parse().unwrap()),
                ],
            );
        }
        self.add(
            Layer::ReceiveV6,
            80,
            true,
            vec![
                Protocol(17),
                LocalPort(546),
                RemotePort(547),
                Remote("fe80::/10".parse().unwrap()),
            ],
        );
        self.add(
            Layer::ConnectV6,
            80,
            true,
            vec![
                Protocol(58),
                IcmpType(133),
                IcmpCode(0),
                Remote("ff02::2/128".parse().unwrap()),
            ],
        );
        for kind in [134, 137] {
            self.add(
                Layer::ReceiveV6,
                80,
                true,
                vec![
                    Protocol(58),
                    IcmpType(kind),
                    IcmpCode(0),
                    Remote("fe80::/10".parse().unwrap()),
                ],
            );
        }
        for layer in [Layer::ConnectV6, Layer::ReceiveV6] {
            for kind in [135, 136] {
                self.add(
                    layer,
                    80,
                    true,
                    vec![Protocol(58), IcmpType(kind), IcmpCode(0)],
                );
            }
        }
    }

    fn add(&mut self, layer: Layer, weight: u64, permit: bool, conditions: Vec<Condition>) {
        self.rules.push(Rule {
            layer,
            weight,
            permit,
            boot: false,
            conditions,
            bind_address: None,
        });
    }
}

pub(crate) fn host(address: IpAddr) -> IpNet {
    IpNet::new(address, if address.is_ipv4() { 32 } else { 128 }).expect("host prefix")
}
pub(crate) fn lan_routes() -> Vec<IpNet> {
    [
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "169.254.0.0/16",
        "224.0.0.0/4",
        "255.255.255.255/32",
        "fc00::/7",
        "fe80::/10",
        "ff00::/8",
    ]
    .into_iter()
    .map(|value| value.parse().expect("built-in LAN range"))
    .collect()
}
