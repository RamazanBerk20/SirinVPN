//! Tunnel.

use super::*;

impl<R: CommandRunner> LinuxNetworkHelper<R> {
    pub(super) fn apply(
        &self,
        request: &TunnelConnectRequest,
        endpoint: IpAddr,
        persistent_protection: bool,
    ) -> Result<()> {
        let wireguard_endpoint = if request.transport == TransportKind::DirectUdp {
            self.stop_transport();
            SocketAddr::new(endpoint, request.endpoint_port).to_string()
        } else {
            self.start_transport(request, endpoint)?;
            format!("127.0.0.1:{}", cleanup::carrier_port(request.transport))
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
        let relayed = request.transport != TransportKind::DirectUdp;
        let listen_port = WIREGUARD_LISTEN_PORT.to_string();
        let mut arguments = vec!["set", INTERFACE_NAME, "private-key", "/dev/stdin"];
        // Only a loopback relay needs WireGuard's port fixed; Direct UDP keeps the
        // kernel's ephemeral source port on the outer path.
        if relayed {
            arguments.extend(["listen-port", listen_port.as_str()]);
        }
        arguments.extend([
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
        ]);
        self.runner
            .run("wg", &arguments, Some(private_key.as_bytes()))
            .map_err(|error| self.listen_port_error(relayed, error))?;
        // stdin already carried the private key; the link stays down until both are set.
        if let Some(preshared_key) = &request.preshared_key {
            let preshared_key = Zeroizing::new(format!("{preshared_key}\n"));
            self.runner.run(
                "wg",
                &[
                    "set",
                    INTERFACE_NAME,
                    "peer",
                    &request.server_public_key,
                    "preshared-key",
                    "/dev/stdin",
                ],
                Some(preshared_key.as_bytes()),
            )?;
        }
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
        for (route, marked, table) in subnet_route_rules(request) {
            let mut rule = vec!["-4", "rule", "add", "to", route];
            if marked {
                rule.extend(["fwmark", ROUTING_TABLE]);
            }
            rule.extend(["table", table, "priority", SUBNET_RULE_PRIORITY]);
            self.runner.run("ip", &rule, None)?;
        }
        self.runner
            .kick_tunnel(request.client_address, request.dns_address);
        if request.routing.mode == TunnelRoutingMode::SelectedApplications {
            self.apply_application_routing(request)?;
        }
        // As wg-quick does: reverse-path filtering must use the restored carrier
        // mark, or strict rp_filter drops server replies on the physical link.
        // Best effort; loose or disabled rp_filter does not need it.
        let _ = self.runner.run(
            "sysctl",
            &["-q", "-w", "net.ipv4.conf.all.src_valid_mark=1"],
            None,
        );
        let firewall = client_firewall(request);
        self.runner
            .run("nft", &["-f", "-"], Some(firewall.as_bytes()))?;
        if !persistent_protection
            && request.client_ipv6_address.is_none()
            && request.routing.mode == TunnelRoutingMode::FullTunnel
        {
            let outer = request.outer_address(endpoint).unwrap_or(endpoint);
            let firewall = transient_ipv6_firewall(request.routing.allow_lan, request, outer);
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

    /// Fixes WireGuard's port on a live interface before a relay carrier starts, or with
    /// `relayed == false` gives it back a random port (0) after a handoff to Direct UDP.
    pub(super) fn pin_wireguard_port(&self, relayed: bool) -> Result<()> {
        let port = if relayed { WIREGUARD_LISTEN_PORT } else { 0 };
        self.runner
            .run(
                "wg",
                &["set", INTERFACE_NAME, "listen-port", &port.to_string()],
                None,
            )
            .map_err(|error| self.listen_port_error(relayed, error))
    }

    /// A taken WireGuard port is reported like a taken relay port, not as a generic
    /// WireGuard failure.
    fn listen_port_error(&self, relayed: bool, error: anyhow::Error) -> anyhow::Error {
        let port = format!(":{WIREGUARD_LISTEN_PORT}");
        let taken = relayed
            && self
                .runner
                .output("ss", &["-H", "-u", "-a", "-n", "sport", "=", &port])
                .is_ok_and(|sockets| sockets.iter().any(|byte| !byte.is_ascii_whitespace()));
        if taken {
            cleanup::CarrierPortInUse(WIREGUARD_LISTEN_PORT).into()
        } else {
            error
        }
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
