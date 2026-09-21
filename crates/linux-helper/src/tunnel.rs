//! Tunnel.

use super::*;

impl<R: CommandRunner> LinuxNetworkHelper<R> {
    pub(super) fn apply(
        &self,
        request: &TunnelConnectRequest,
        endpoint: IpAddr,
        persistent_protection: bool,
    ) -> Result<()> {
        let wireguard_endpoint = match request.transport {
            TransportKind::DirectUdp => {
                self.stop_transport();
                SocketAddr::new(endpoint, request.endpoint_port).to_string()
            }
            TransportKind::ObfuscatedUdp => {
                self.start_transport(request, endpoint)?;
                format!("127.0.0.1:{CLIENT_RELAY_PORT}")
            }
            TransportKind::TcpFallback => {
                self.start_transport(request, endpoint)?;
                format!("127.0.0.1:{TCP_CLIENT_RELAY_PORT}")
            }
            TransportKind::TlsLike => {
                self.start_transport(request, endpoint)?;
                format!("127.0.0.1:{TLS_LIKE_CLIENT_RELAY_PORT}")
            }
        };
        self.runner.run(
            "ip",
            &["link", "add", INTERFACE_NAME, "type", "wireguard"],
            None,
        )?;
        let mut private_key = Zeroizing::new(request.private_key.clone());
        private_key.push('\n');
        let mtu = mtu::session_mtu(request).to_string();
        let allowed_ips = wireguard_allowed_ips(request);
        self.runner.run(
            "wg",
            &[
                "set",
                INTERFACE_NAME,
                "private-key",
                "/dev/stdin",
                "fwmark",
                ROUTING_TABLE,
                "peer",
                &request.server_public_key,
                "endpoint",
                &wireguard_endpoint,
                "allowed-ips",
                &allowed_ips,
                "persistent-keepalive",
                "25",
            ],
            Some(private_key.as_bytes()),
        )?;
        self.runner.run(
            "ip",
            &[
                "address",
                "replace",
                &format!("{}/32", request.client_address),
                "dev",
                INTERFACE_NAME,
            ],
            None,
        )?;
        if let Some(client_ipv6_address) = request.client_ipv6_address {
            self.runner.run(
                "ip",
                &[
                    "-6",
                    "address",
                    "replace",
                    &format!("{client_ipv6_address}/128"),
                    "dev",
                    INTERFACE_NAME,
                    "nodad",
                ],
                None,
            )?;
        }
        self.runner.run(
            "ip",
            &["link", "set", "mtu", &mtu, "up", "dev", INTERFACE_NAME],
            None,
        )?;
        self.apply_policy_routes(request, "-4")?;
        if request.client_ipv6_address.is_some() && routing_uses_ipv6(&request.routing) {
            self.apply_policy_routes(request, "-6")?;
        }
        self.apply_lan_exceptions(request)?;
        self.runner
            .kick_tunnel(request.client_address, request.dns_address);
        if request.routing.mode == TunnelRoutingMode::SelectedApplications {
            self.apply_application_routing(request)?;
        }
        self.runner
            .run("nft", &["-f", "-"], Some(CLIENT_FIREWALL.as_bytes()))?;
        if !persistent_protection
            && request.client_ipv6_address.is_none()
            && request.routing.mode == TunnelRoutingMode::FullTunnel
        {
            let firewall = transient_ipv6_firewall(request.routing.allow_lan, request, endpoint);
            self.runner
                .run("nft", &["-f", "-"], Some(firewall.as_bytes()))?;
        }
        if request.routing.mode == TunnelRoutingMode::SelectedApplications {
            return Ok(());
        }
        self.runner.run(
            "resolvectl",
            &["dns", INTERFACE_NAME, &request.dns_address.to_string()],
            None,
        )?;
        self.runner
            .run("resolvectl", &["domain", INTERFACE_NAME, "~."], None)?;
        self.runner.run(
            "resolvectl",
            &["default-route", INTERFACE_NAME, "yes"],
            None,
        )?;
        Ok(())
    }

    pub(super) fn apply_policy_routes(
        &self,
        request: &TunnelConnectRequest,
        family: &str,
    ) -> Result<()> {
        for route in route_table_destinations(request, family) {
            self.runner.run(
                "ip",
                &[
                    family,
                    "route",
                    "add",
                    &route,
                    "dev",
                    INTERFACE_NAME,
                    "table",
                    ROUTING_TABLE,
                ],
                None,
            )?;
        }
        let mut rule = vec![family, "rule", "add"];
        if request.routing.mode == TunnelRoutingMode::SelectedApplications {
            rule.extend(["iif", applications::HOST_LINK]);
        } else {
            rule.extend(["not", "fwmark", ROUTING_TABLE]);
        }
        rule.extend(["table", ROUTING_TABLE, "priority", RULE_TUNNEL_PRIORITY]);
        self.runner.run("ip", &rule, None)?;
        if request.routing.mode == TunnelRoutingMode::FullTunnel {
            self.runner.run(
                "ip",
                &[
                    family,
                    "rule",
                    "add",
                    "table",
                    "main",
                    "suppress_prefixlength",
                    "0",
                    "priority",
                    RULE_MAIN_PRIORITY,
                ],
                None,
            )?;
        }
        Ok(())
    }

    pub(super) fn apply_lan_exceptions(&self, request: &TunnelConnectRequest) -> Result<()> {
        if request.routing.mode == TunnelRoutingMode::SelectedApplications {
            return self.apply_application_exceptions(request);
        }
        if !request.routing.allow_lan
            && request.routing.mode != TunnelRoutingMode::SelectedApplications
        {
            return Ok(());
        }
        let dns_route = format!("{}/32", request.dns_address);
        self.runner.run(
            "ip",
            &[
                "-4",
                "rule",
                "add",
                "to",
                &dns_route,
                "table",
                ROUTING_TABLE,
                "priority",
                DNS_RULE_PRIORITY,
            ],
            None,
        )?;
        if !request.routing.allow_lan {
            return Ok(());
        }
        for (family, routes) in [
            ("-4", IPV4_LAN_ROUTES.as_slice()),
            ("-6", IPV6_LAN_ROUTES.as_slice()),
        ] {
            for (index, route) in routes.iter().enumerate() {
                let priority = (LAN_RULE_PRIORITY_START + index as u16).to_string();
                let mut arguments = vec![family, "rule", "add"];
                if request.routing.mode == TunnelRoutingMode::SelectedApplications {
                    if family == "-6" {
                        continue;
                    }
                    arguments.extend(["iif", applications::HOST_LINK]);
                }
                arguments.extend(["to", route, "table", "main", "priority", &priority]);
                self.runner.run("ip", &arguments, None)?;
            }
        }
        Ok(())
    }
}
