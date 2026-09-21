//! Ownership.

use super::*;
use crate::cleanup::carrier_unit;

impl<R: CommandRunner> LinuxNetworkHelper<R> {
    pub(super) fn ensure_ownership(&self) -> Result<(), HelperError> {
        if self.state_path().exists() || self.persistent_path().exists() {
            return Ok(());
        }
        if self.owned_state_exists()? {
            return Err(HelperError::OwnershipConflict);
        }
        Ok(())
    }

    pub(super) fn owned_state_exists(&self) -> Result<bool, HelperError> {
        let interface_exists = self
            .runner
            .succeeds("ip", &["link", "show", INTERFACE_NAME]);
        let route_table_output = self
            .runner
            .output("ip", &["-details", "-4", "route", "show", "table", "all"])
            .map_err(|_| HelperError::NetworkOperationFailed)?;
        let route_table_in_use = route_output_contains_table(&route_table_output, ROUTING_TABLE);
        let ipv6_route_table_output = self
            .runner
            .output("ip", &["-details", "-6", "route", "show", "table", "all"])
            .map_err(|_| HelperError::NetworkOperationFailed)?;
        let ipv6_route_table_in_use =
            route_output_contains_table(&ipv6_route_table_output, ROUTING_TABLE);
        let tunnel_priority_in_use = self
            .runner
            .output(
                "ip",
                &["-4", "rule", "show", "priority", RULE_TUNNEL_PRIORITY],
            )
            .map_err(|_| HelperError::NetworkOperationFailed)?
            .iter()
            .any(|byte| !byte.is_ascii_whitespace());
        let main_priority_in_use = self
            .runner
            .output(
                "ip",
                &["-4", "rule", "show", "priority", RULE_MAIN_PRIORITY],
            )
            .map_err(|_| HelperError::NetworkOperationFailed)?
            .iter()
            .any(|byte| !byte.is_ascii_whitespace());
        let ipv6_tunnel_priority_in_use = self
            .runner
            .output(
                "ip",
                &["-6", "rule", "show", "priority", RULE_TUNNEL_PRIORITY],
            )
            .map_err(|_| HelperError::NetworkOperationFailed)?
            .iter()
            .any(|byte| !byte.is_ascii_whitespace());
        let ipv6_main_priority_in_use = self
            .runner
            .output(
                "ip",
                &["-6", "rule", "show", "priority", RULE_MAIN_PRIORITY],
            )
            .map_err(|_| HelperError::NetworkOperationFailed)?
            .iter()
            .any(|byte| !byte.is_ascii_whitespace());
        let firewall_table_in_use = self
            .runner
            .succeeds("nft", &["list", "table", "inet", "sirinvpn_client"]);
        let ipv6_table_in_use = self
            .runner
            .succeeds("nft", &["list", "table", "ip6", "sirinvpn_client6"]);
        let routing_exception_in_use = self.any_routing_exception_rule_exists();
        let kill_switch_in_use = self.kill_switch_exists();
        let application_guard_in_use = self
            .runner
            .succeeds("nft", &["list", "table", "inet", "sirinvpn_apps"]);
        Ok(interface_exists
            || route_table_in_use
            || ipv6_route_table_in_use
            || tunnel_priority_in_use
            || main_priority_in_use
            || ipv6_tunnel_priority_in_use
            || ipv6_main_priority_in_use
            || firewall_table_in_use
            || ipv6_table_in_use
            || routing_exception_in_use
            || kill_switch_in_use
            || application_guard_in_use)
    }

    pub(super) fn tunnel_configuration_exists(&self, request: &TunnelConnectRequest) -> bool {
        if !self
            .runner
            .succeeds("ip", &["link", "show", INTERFACE_NAME])
        {
            return false;
        }
        let routes_exist = self
            .runner
            .output("ip", &["-details", "-4", "route", "show", "table", "all"])
            .is_ok_and(|output| {
                route_table_destinations(request, "-4").iter().all(|route| {
                    route_output_contains_owned_destination(&output, route, ROUTING_TABLE)
                })
            });
        let tunnel_rule_exists = self
            .runner
            .output(
                "ip",
                &["-4", "rule", "show", "priority", RULE_TUNNEL_PRIORITY],
            )
            .is_ok_and(|output| output.iter().any(|byte| !byte.is_ascii_whitespace()));
        let main_rule_exists = self
            .runner
            .output(
                "ip",
                &["-4", "rule", "show", "priority", RULE_MAIN_PRIORITY],
            )
            .is_ok_and(|output| output.iter().any(|byte| !byte.is_ascii_whitespace()));
        let ipv4_exists = routes_exist
            && tunnel_rule_exists
            && (request.routing.mode != TunnelRoutingMode::FullTunnel || main_rule_exists)
            && self.routing_exception_rules_exist(request)
            && self
                .runner
                .succeeds("nft", &["list", "table", "inet", "sirinvpn_client"]);
        let transport_exists = request.transport == TransportKind::DirectUdp
            || self.runner.succeeds(
                "systemctl",
                &["is-active", "--quiet", &carrier_unit(request.transport)],
            )
            || (self.transport_config_path().exists()
                && self
                    .runner
                    .succeeds("systemctl", &["is-active", "--quiet", TRANSPORT_UNIT]));
        ipv4_exists
            && (request.routing.mode != TunnelRoutingMode::SelectedApplications
                || self.application_configuration_exists(request))
            && transport_exists
            && (!routing_uses_ipv6(&request.routing)
                || request.client_ipv6_address.is_none()
                || request.client_ipv6_address.is_some_and(|address| {
                    self.ipv6_tunnel_configuration_exists(address, &request.routing)
                }))
    }

    pub(super) fn ipv6_tunnel_configuration_exists(
        &self,
        expected_address: Ipv6Addr,
        routing: &TunnelRoutingPolicy,
    ) -> bool {
        let expected_address = format!("{expected_address}/128");
        let address_exists = self
            .runner
            .output(
                "ip",
                &["-o", "-6", "address", "show", "dev", INTERFACE_NAME],
            )
            .is_ok_and(|output| output_contains_token(&output, &expected_address));
        let routes_exist = self
            .runner
            .output("ip", &["-details", "-6", "route", "show", "table", "all"])
            .is_ok_and(|output| {
                routing_family_destinations(routing, true)
                    .iter()
                    .all(|route| {
                        route_output_contains_owned_destination(&output, route, ROUTING_TABLE)
                    })
            });
        let tunnel_rule_exists = self
            .runner
            .output(
                "ip",
                &["-6", "rule", "show", "priority", RULE_TUNNEL_PRIORITY],
            )
            .is_ok_and(|output| output.iter().any(|byte| !byte.is_ascii_whitespace()));
        let main_rule_exists = self
            .runner
            .output(
                "ip",
                &["-6", "rule", "show", "priority", RULE_MAIN_PRIORITY],
            )
            .is_ok_and(|output| output.iter().any(|byte| !byte.is_ascii_whitespace()));
        address_exists
            && routes_exist
            && tunnel_rule_exists
            && (routing.mode != TunnelRoutingMode::FullTunnel || main_rule_exists)
    }

    pub(super) fn latest_handshake_timestamp(&self) -> Option<u64> {
        self.runner
            .output("wg", &["show", INTERFACE_NAME, "latest-handshakes"])
            .ok()
            .map(|output| latest_handshake(&output).unwrap_or(0))
    }

    pub(super) fn physical_default_route_fingerprint(&self) -> Option<Option<u64>> {
        let output = self
            .runner
            .output("ip", &["-4", "route", "show", "table", "main", "default"])
            .ok()?;
        let output = std::str::from_utf8(&output).ok()?;
        let ipv4 = default_route_fingerprint(output);
        let ipv6 = self
            .runner
            .output("ip", &["-6", "route", "show", "table", "main", "default"])
            .ok()
            .and_then(|bytes| {
                std::str::from_utf8(&bytes)
                    .ok()
                    .and_then(default_route_fingerprint)
            });
        Some(match (ipv4, ipv6) {
            (Some(v4), Some(v6)) => {
                let mut combined = DefaultHasher::new();
                (v4, v6).hash(&mut combined);
                Some(combined.finish())
            }
            (v4, v6) => v4.or(v6),
        })
    }

    pub(super) fn kill_switch_exists(&self) -> bool {
        self.runner
            .succeeds("nft", &["list", "table", "inet", "sirinvpn_guard"])
    }

    pub(super) fn routing_exception_rules_exist(&self, request: &TunnelConnectRequest) -> bool {
        if !request.routing.allow_lan
            && request.routing.mode != TunnelRoutingMode::SelectedApplications
        {
            return true;
        }
        let dns_route = format!("{}/32", request.dns_address);
        if !self.rule_matches("-4", DNS_RULE_PRIORITY, &dns_route, ROUTING_TABLE) {
            return false;
        }
        if !request.routing.allow_lan {
            return true;
        }
        if request.routing.mode == TunnelRoutingMode::SelectedApplications {
            return true; // The application guard and fallback rules are inspected separately.
        }
        [
            ("-4", IPV4_LAN_ROUTES.as_slice()),
            ("-6", IPV6_LAN_ROUTES.as_slice()),
        ]
        .into_iter()
        .all(|(family, routes)| {
            routes.iter().enumerate().all(|(index, route)| {
                let priority = (LAN_RULE_PRIORITY_START + index as u16).to_string();
                self.rule_matches(family, &priority, route, "main")
            })
        })
    }

    pub(super) fn rule_matches(
        &self,
        family: &str,
        priority: &str,
        destination: &str,
        table: &str,
    ) -> bool {
        self.runner
            .output("ip", &[family, "rule", "show", "priority", priority])
            .is_ok_and(|output| rule_output_contains_destination_table(&output, destination, table))
    }

    pub(super) fn rule_priority_exists(&self, family: &str, priority: &str) -> bool {
        self.runner
            .output("ip", &[family, "rule", "show", "priority", priority])
            .is_ok_and(|output| output.iter().any(|byte| !byte.is_ascii_whitespace()))
    }

    pub(super) fn any_routing_exception_rule_exists(&self) -> bool {
        ["-4", "-6"].into_iter().any(|family| {
            self.rule_priority_exists(family, DNS_RULE_PRIORITY)
                || self.rule_priority_exists(family, "10002")
                || (0..=IPV4_LAN_ROUTES.len()).any(|index| {
                    let priority = (LAN_RULE_PRIORITY_START + index as u16).to_string();
                    self.rule_priority_exists(family, &priority)
                })
        })
    }

    pub(super) fn apply_kill_switch(
        &self,
        request: &TunnelConnectRequest,
        endpoint: IpAddr,
    ) -> Result<(), HelperError> {
        let firewall = kill_switch_firewall(request, endpoint, self.kill_switch_exists());
        self.runner
            .run("nft", &["-f", "-"], Some(firewall.as_bytes()))
            .map_err(|_| HelperError::PersistentProtectionUnavailable)
    }

    pub(super) fn owned_tunnel_state_exists(&self) -> Result<bool, HelperError> {
        let interface_exists = self
            .runner
            .succeeds("ip", &["link", "show", INTERFACE_NAME]);
        let route_table_output = self
            .runner
            .output("ip", &["-details", "-4", "route", "show", "table", "all"])
            .map_err(|_| HelperError::NetworkOperationFailed)?;
        let route_table_in_use = route_output_contains_table(&route_table_output, ROUTING_TABLE);
        let ipv6_route_table_output = self
            .runner
            .output("ip", &["-details", "-6", "route", "show", "table", "all"])
            .map_err(|_| HelperError::NetworkOperationFailed)?;
        let ipv6_route_table_in_use =
            route_output_contains_table(&ipv6_route_table_output, ROUTING_TABLE);
        let tunnel_priority_in_use = self
            .runner
            .output(
                "ip",
                &["-4", "rule", "show", "priority", RULE_TUNNEL_PRIORITY],
            )
            .map_err(|_| HelperError::NetworkOperationFailed)?
            .iter()
            .any(|byte| !byte.is_ascii_whitespace());
        let main_priority_in_use = self
            .runner
            .output(
                "ip",
                &["-4", "rule", "show", "priority", RULE_MAIN_PRIORITY],
            )
            .map_err(|_| HelperError::NetworkOperationFailed)?
            .iter()
            .any(|byte| !byte.is_ascii_whitespace());
        let ipv6_tunnel_priority_in_use = self
            .runner
            .output(
                "ip",
                &["-6", "rule", "show", "priority", RULE_TUNNEL_PRIORITY],
            )
            .map_err(|_| HelperError::NetworkOperationFailed)?
            .iter()
            .any(|byte| !byte.is_ascii_whitespace());
        let ipv6_main_priority_in_use = self
            .runner
            .output(
                "ip",
                &["-6", "rule", "show", "priority", RULE_MAIN_PRIORITY],
            )
            .map_err(|_| HelperError::NetworkOperationFailed)?
            .iter()
            .any(|byte| !byte.is_ascii_whitespace());
        let firewall_table_in_use = self
            .runner
            .succeeds("nft", &["list", "table", "inet", "sirinvpn_client"]);
        let ipv6_table_in_use = self
            .runner
            .succeeds("nft", &["list", "table", "ip6", "sirinvpn_client6"]);
        let routing_exception_in_use = self.any_routing_exception_rule_exists();
        Ok(interface_exists
            || route_table_in_use
            || ipv6_route_table_in_use
            || tunnel_priority_in_use
            || main_priority_in_use
            || ipv6_tunnel_priority_in_use
            || ipv6_main_priority_in_use
            || firewall_table_in_use
            || ipv6_table_in_use
            || routing_exception_in_use)
    }

    pub(super) fn rollback_persistent_start(&self) {
        let _ = self
            .runner
            .run("systemctl", &["stop", RECONNECT_UNIT], None);
        if let Ok(_lock) = self.lock_operations() {
            let _ = self.cleanup_all_owned();
            let _ = remove_file_if_exists(&self.state_path());
            let _ = remove_file_if_exists(&self.persistent_path());
        }
        let _ = self.runner.run(
            "systemctl",
            &["disable", KILL_SWITCH_UNIT, RECONNECT_UNIT],
            None,
        );
        let _ = self
            .runner
            .run("systemctl", &["stop", KILL_SWITCH_UNIT], None);
    }

    pub(super) fn state_path(&self) -> PathBuf {
        self.runtime_directory.join("client-state.json")
    }

    pub(super) fn transport_config_path(&self) -> PathBuf {
        self.runtime_directory.join("transport.json")
    }

    pub(super) fn write_state(&self, state: &RuntimeState) -> Result<()> {
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o755)
            .create(&self.runtime_directory)?;
        let path = self.state_path();
        let temporary = path.with_extension("new");
        let bytes = serde_json::to_vec(state)?;
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o644)
            .open(&temporary)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        fs::set_permissions(&temporary, fs::Permissions::from_mode(0o644))?;
        fs::rename(temporary, path)?;
        Ok(())
    }

    pub(super) fn read_state(&self) -> Result<RuntimeState, HelperError> {
        let bytes = fs::read(self.state_path()).map_err(|_| HelperError::InvalidState)?;
        let state: RuntimeState =
            serde_json::from_slice(&bytes).map_err(|_| HelperError::InvalidState)?;
        if !matches!(state.schema_version, 1..=5)
            || (state.schema_version >= 3) != state.policy.is_some()
            || (state.schema_version < 5
                && (state.schema_version == 4) != state.endpoint_monitor.is_some())
            || (state.schema_version == 5)
                != (state.routing.mode == TunnelRoutingMode::SelectedApplications)
            || state
                .endpoint_monitor
                .as_ref()
                .is_some_and(|monitor| !monitor.valid(state.server_id))
            || state
                .quality
                .as_ref()
                .is_some_and(|quality| !quality.valid())
            || state.mtu.is_some_and(|mtu| {
                let minimum = if state.client_ipv6_address.is_some() {
                    1280
                } else {
                    576
                };
                state.policy.is_none()
                    || !(minimum..=1420).contains(&mtu.configured)
                    || mtu
                        .suggested
                        .is_some_and(|value| !(minimum..=1420).contains(&value))
                    || mtu
                        .policy
                        .validate(state.client_ipv6_address.is_some())
                        .is_err()
            })
        {
            return Err(HelperError::InvalidState);
        }
        Ok(state)
    }

    pub(super) fn write_persistent(&self, state: &PersistentConnection) -> Result<(), HelperError> {
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&self.persistent_directory)
            .map_err(|_| HelperError::PersistentProtectionUnavailable)?;
        fs::set_permissions(
            &self.persistent_directory,
            fs::Permissions::from_mode(0o700),
        )
        .map_err(|_| HelperError::PersistentProtectionUnavailable)?;
        let path = self.persistent_path();
        let temporary = path.with_extension("new");
        let bytes = Zeroizing::new(
            serde_json::to_vec(state).map_err(|_| HelperError::PersistentProtectionUnavailable)?,
        );
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&temporary)
            .map_err(|_| HelperError::PersistentProtectionUnavailable)?;
        file.write_all(&bytes)
            .map_err(|_| HelperError::PersistentProtectionUnavailable)?;
        file.sync_all()
            .map_err(|_| HelperError::PersistentProtectionUnavailable)?;
        fs::set_permissions(&temporary, fs::Permissions::from_mode(0o600))
            .map_err(|_| HelperError::PersistentProtectionUnavailable)?;
        fs::rename(temporary, path).map_err(|_| HelperError::PersistentProtectionUnavailable)?;
        fs::File::open(&self.persistent_directory)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| HelperError::PersistentProtectionUnavailable)
    }

    pub(super) fn read_persistent(&self) -> Result<PersistentConnection, HelperError> {
        let bytes = Zeroizing::new(
            fs::read(self.persistent_path()).map_err(|_| HelperError::InvalidState)?,
        );
        let mut state: PersistentConnection =
            serde_json::from_slice(&bytes).map_err(|_| HelperError::InvalidState)?;
        if matches!(state.schema_version, 2..=6) {
            if state.request.schema_version
                != match state.schema_version {
                    6 => 11,
                    5 => 10,
                    4 => 9,
                    3 => 8,
                    _ => 7,
                }
                || state.request.policy.is_none()
                || state.obfuscated_udp.is_some()
                || state.tcp_fallback.is_some()
                || state.extended_routing.is_some()
            {
                return Err(HelperError::InvalidState);
            }
            validate_request(&state.request)?;
            if !endpoints::validate_resolved(&state) {
                return Err(HelperError::InvalidState);
            }
            return Ok(state);
        }
        if state.schema_version != 1 || !state.request.persistent_protection {
            return Err(HelperError::InvalidState);
        }
        if state.obfuscated_udp.is_some() && state.tcp_fallback.is_some() {
            return Err(HelperError::InvalidState);
        }
        if let Some(obfuscated) = state.obfuscated_udp.take() {
            if state.request.transport != TransportKind::DirectUdp
                || state.request.server_transport_public_key.is_some()
                || state.request.server_certificate_sha256.is_some()
                || state.request.schema_version > 2
            {
                return Err(HelperError::InvalidState);
            }
            state.request.schema_version = 3;
            state.request.transport = TransportKind::ObfuscatedUdp;
            state.request.server_transport_public_key =
                Some(obfuscated.server_transport_public_key);
        }
        if let Some(tcp) = state.tcp_fallback.take() {
            if state.request.transport != TransportKind::DirectUdp
                || state.request.server_transport_public_key.is_some()
                || state.request.server_certificate_sha256.is_some()
                || state.request.schema_version > 2
            {
                return Err(HelperError::InvalidState);
            }
            state.request.schema_version = 4;
            state.request.transport = TransportKind::TcpFallback;
            state.request.server_transport_public_key = Some(tcp.server_transport_public_key);
        }
        if let Some(routing) = state.extended_routing.take() {
            if routing.is_legacy_default() || !state.request.routing.is_legacy_default() {
                return Err(HelperError::InvalidState);
            }
            state.request.schema_version = 6;
            state.request.routing = routing;
        }
        validate_request(&state.request)?;
        Ok(state)
    }
}
