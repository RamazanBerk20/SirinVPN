//! Lifecycle.

use super::*;

impl<R: CommandRunner> LinuxNetworkHelper<R> {
    pub fn connect(
        &self,
        request: &TunnelConnectRequest,
    ) -> Result<LocalTunnelStatus, HelperError> {
        validate_request(request)?;
        if request.policy.is_some() {
            self.connect_with_policy(request)
        } else if request.persistent_protection {
            self.connect_persistent(request)
        } else {
            self.connect_transient(request)
        }
    }

    pub(super) fn connect_transient(
        &self,
        request: &TunnelConnectRequest,
    ) -> Result<LocalTunnelStatus, HelperError> {
        if self.persistent_path().exists() {
            return Err(HelperError::PersistentProtectionUnavailable);
        }
        let endpoint = resolve_endpoint(&request.endpoint_host, request.endpoint_port)?;
        let _lock = self.lock_operations()?;
        self.ensure_ownership()?;
        if self.state_path().exists() {
            self.cleanup_tunnel_owned()?;
        }
        self.write_state(&RuntimeState {
            application_guard_verified: None,
            mtu: None,
            mtu_sampled_at_unix: None,
            quality: None,
            endpoint_monitor: None,
            policy: None,
            has_connected: false,
            initial_attempts: 0,
            waiting_for_user: false,
            enforcement: None,
            observed_at_boot_seconds: None,
            schema_version: 2,
            server_id: request.server_id,
            persistent_protection: false,
            reconnecting: false,
            applied_at_unix: now_unix(),
            client_ipv6_address: request.client_ipv6_address,
            transport: request.transport,
            transport_fallback_enabled: false,
            routing: request.routing.clone(),
            dns_address: request.routing.allow_lan.then_some(request.dns_address),
        })
        .map_err(|_| HelperError::NetworkOperationFailed)?;
        if self.apply(request, endpoint, false).is_err() {
            if self.cleanup_tunnel_owned().is_ok() {
                let _ = fs::remove_file(self.state_path());
            }
            return Err(HelperError::NetworkOperationFailed);
        }
        self.status()
    }

    pub(super) fn connect_persistent(
        &self,
        request: &TunnelConnectRequest,
    ) -> Result<LocalTunnelStatus, HelperError> {
        let endpoint = resolve_endpoint(&request.endpoint_host, request.endpoint_port)?;
        {
            let _lock = self.lock_operations()?;
            self.ensure_ownership()?;
            let (persistent_request, obfuscated_udp, tcp_fallback, extended_routing) =
                persistent_request_for_rollback(request);
            self.write_persistent(&PersistentConnection {
                resolved_endpoints: Vec::new(),
                schema_version: 1,
                request: persistent_request,
                endpoint,
                obfuscated_udp,
                tcp_fallback,
                extended_routing,
            })?;
            self.write_state(&RuntimeState {
                application_guard_verified: None,
                mtu: None,
                mtu_sampled_at_unix: None,
                quality: None,
                endpoint_monitor: None,
                policy: None,
                has_connected: false,
                initial_attempts: 0,
                waiting_for_user: false,
                enforcement: None,
                observed_at_boot_seconds: None,
                schema_version: 2,
                server_id: request.server_id,
                persistent_protection: true,
                reconnecting: true,
                applied_at_unix: now_unix(),
                client_ipv6_address: request.client_ipv6_address,
                transport: request.transport,
                transport_fallback_enabled: !request.reconnect_candidates.is_empty(),
                routing: request.routing.clone(),
                dns_address: request.routing.allow_lan.then_some(request.dns_address),
            })
            .map_err(|_| HelperError::PersistentProtectionUnavailable)?;
        }

        if self.start_persistent_services().is_err() {
            self.rollback_persistent_start();
            return Err(HelperError::PersistentProtectionUnavailable);
        }
        if self.apply_kill_switch(request, endpoint).is_err() {
            self.rollback_persistent_start();
            return Err(HelperError::PersistentProtectionUnavailable);
        }
        if self.reconcile_persistent_once(false).is_err() {
            self.rollback_persistent_start();
            return Err(HelperError::PersistentProtectionUnavailable);
        }
        self.status()
    }

    pub fn disconnect(&self) -> Result<LocalTunnelStatus, HelperError> {
        let persistent = self.persistent_path().exists();
        if persistent
            && self
                .runner
                .run("systemctl", &["stop", RECONNECT_UNIT], None)
                .is_err()
        {
            return Err(HelperError::NetworkOperationFailed);
        }
        let _lock = self.lock_operations()?;
        self.ensure_ownership()?;
        // Permission or inspection failure is not evidence of an absent block.
        self.guard_is_absent()?;
        self.cleanup_all_owned()?;
        if !self.guard_is_absent()? {
            return Err(HelperError::NetworkOperationFailed);
        }
        remove_file_if_exists(&self.state_path())
            .map_err(|_| HelperError::NetworkOperationFailed)?;
        remove_file_if_exists(&self.persistent_path())
            .map_err(|_| HelperError::NetworkOperationFailed)?;
        if persistent {
            let _ = self
                .runner
                .run("systemctl", &["stop", KILL_SWITCH_UNIT], None);
            let _ = self.runner.run(
                "systemctl",
                &["disable", KILL_SWITCH_UNIT, RECONNECT_UNIT],
                None,
            );
        }
        Ok(disconnected_status())
    }

    pub fn status(&self) -> Result<LocalTunnelStatus, HelperError> {
        let mut status = self.tunnel_status()?;
        status.startup_service_enabled = startup_service_enabled(&self.runner);
        Ok(status)
    }

    fn tunnel_status(&self) -> Result<LocalTunnelStatus, HelperError> {
        let state = match self.read_state() {
            Ok(state) => state,
            Err(HelperError::InvalidState) if !self.state_path().exists() => {
                return Ok(disconnected_status());
            }
            Err(error) => return Err(error),
        };
        if !self
            .runner
            .succeeds("ip", &["link", "show", INTERFACE_NAME])
        {
            // The interface can disappear between monitor samples. A fresh,
            // verified guard then blocks traffic; it is no longer merely armed.
            let enforcement = match state.effective_kill_switch() {
                KillSwitchState::Armed => KillSwitchState::Blocking,
                other => other,
            };
            return Ok(LocalTunnelStatus {
                application_routing_supported: true,
                application_routing_backend: Some(
                    sirinvpn_tunnel_model::ApplicationRoutingBackend::LinuxNamespace,
                ),
                application_routing_ready: (state.routing.mode
                    == TunnelRoutingMode::SelectedApplications)
                    .then_some(false),
                transport_quality_supported: true,
                transport_quality: state.quality.as_ref().map(|q| q.snapshot(false)),
                mtu_detection_supported: true,
                https_transport_supported: true,
                endpoint_updates_supported: true,
                endpoint_checkpoint: state
                    .endpoint_monitor
                    .as_ref()
                    .and_then(|monitor| monitor.accepted.clone()),
                mtu: state.mtu.map(|mut mtu| {
                    mtu.outcome = sirinvpn_protocol::MtuProbeOutcome::Pending;
                    mtu.suggested = None;
                    mtu
                }),
                connection_control_supported: true,
                recovery_in_progress: state.has_connected
                    && state.reconnecting
                    && !state.waiting_for_user,
                startup_service_enabled: None,
                supervisor_status_known: state.policy.map(|_| state.observation_is_fresh()),
                policy: state.policy,
                independent_policy_supported: true,
                kill_switch_state: Some(enforcement),
                connect_on_startup: state.connection_policy().connect_on_startup,
                waiting_for_user: state.waiting_for_user,
                traffic_metrics_supported: true,
                byte_counters_available: Some(false),
                included_routes: Some(state.routing.included_routes.clone()),
                state: ConnectionState::Degraded,
                interface_name: INTERFACE_NAME.to_owned(),
                server_id: Some(state.server_id),
                rx_bytes: 0,
                tx_bytes: 0,
                rx_packets: None,
                tx_packets: None,
                tunnel_uptime_seconds: None,
                counter_epoch: None,
                ipv6_blocked: if state.policy.is_some() {
                    enforcement == KillSwitchState::Blocking
                        && state.routing.mode == TunnelRoutingMode::FullTunnel
                } else {
                    ipv6_blocked_for_state(&state, false)
                },
                ipv6_tunneled: false,
                transport: Some(state.transport),
                kill_switch_enabled: state.connection_policy().kill_switch,
                auto_reconnect_enabled: state.connection_policy().automatic_reconnect,
                transport_fallback_enabled: state.transport_fallback_enabled,
                routing_mode: state.routing.mode,
                allow_lan: state.routing.allow_lan,
            });
        }
        let rx_bytes = interface_packet_counter("rx_bytes");
        let tx_bytes = interface_packet_counter("tx_bytes");
        let ipv6_tunneled = routing_uses_ipv6(&state.routing)
            && (state.routing.mode != TunnelRoutingMode::SelectedApplications
                || applications::ipv6_forwarding_available())
            && state.client_ipv6_address.is_some_and(|address| {
                self.ipv6_tunnel_configuration_exists(address, &state.routing)
            });
        Ok(LocalTunnelStatus {
            application_routing_supported: true,
            application_routing_backend: Some(
                sirinvpn_tunnel_model::ApplicationRoutingBackend::LinuxNamespace,
            ),
            application_routing_ready: (state.routing.mode
                == TunnelRoutingMode::SelectedApplications)
                .then_some(
                    state.application_guard_verified == Some(true)
                        && state.observation_is_fresh()
                        && state.has_connected
                        && !state.reconnecting
                        && !state.waiting_for_user,
                ),
            transport_quality_supported: true,
            transport_quality: state.quality.as_ref().map(|q| {
                q.snapshot(
                    !state.reconnecting && !state.waiting_for_user && state.observation_is_fresh(),
                )
            }),
            mtu_detection_supported: true,
            https_transport_supported: true,
            endpoint_updates_supported: true,
            endpoint_checkpoint: state
                .endpoint_monitor
                .as_ref()
                .and_then(|monitor| monitor.accepted.clone()),
            mtu: state.mtu,
            connection_control_supported: true,
            recovery_in_progress: state.has_connected
                && state.reconnecting
                && !state.waiting_for_user,
            startup_service_enabled: None,
            supervisor_status_known: state.policy.map(|_| state.observation_is_fresh()),
            policy: state.policy,
            independent_policy_supported: true,
            kill_switch_state: Some(state.effective_kill_switch()),
            connect_on_startup: state.connection_policy().connect_on_startup,
            waiting_for_user: state.waiting_for_user,
            traffic_metrics_supported: true,
            byte_counters_available: Some(rx_bytes.is_some() && tx_bytes.is_some()),
            included_routes: Some(state.routing.included_routes.clone()),
            state: if state.waiting_for_user
                || (state.policy.is_some() && !state.observation_is_fresh())
            {
                ConnectionState::Degraded
            } else if state.reconnecting {
                ConnectionState::Connecting
            } else {
                ConnectionState::Connected
            },
            interface_name: INTERFACE_NAME.to_owned(),
            server_id: Some(state.server_id),
            rx_bytes: rx_bytes.unwrap_or_default(),
            tx_bytes: tx_bytes.unwrap_or_default(),
            rx_packets: interface_packet_counter("rx_packets"),
            tx_packets: interface_packet_counter("tx_packets"),
            tunnel_uptime_seconds: tunnel_age(state.applied_at_unix, now_unix()),
            counter_epoch: fs::read_to_string(format!("/sys/class/net/{INTERFACE_NAME}/ifindex"))
                .ok()
                .and_then(|index| index.trim().parse::<u32>().ok())
                .map(|index| format!("{}:{index}", state.applied_at_unix)),
            ipv6_blocked: if state.policy.is_some() {
                state.routing.mode == TunnelRoutingMode::FullTunnel
                    && !ipv6_tunneled
                    && matches!(
                        state.effective_kill_switch(),
                        KillSwitchState::Armed | KillSwitchState::Blocking
                    )
            } else {
                ipv6_blocked_for_state(&state, ipv6_tunneled)
            },
            ipv6_tunneled,
            transport: Some(state.transport),
            kill_switch_enabled: state.connection_policy().kill_switch,
            auto_reconnect_enabled: state.connection_policy().automatic_reconnect,
            transport_fallback_enabled: state.transport_fallback_enabled,
            routing_mode: state.routing.mode,
            allow_lan: state.routing.allow_lan,
        })
    }
}

// Counters belong to this interface lifetime. A reconnect recreates it; no history is saved.
pub(super) fn interface_packet_counter(name: &str) -> Option<u64> {
    fs::read_to_string(format!("/sys/class/net/{INTERFACE_NAME}/statistics/{name}"))
        .ok()?
        .trim()
        .parse()
        .ok()
}

fn tunnel_age(applied: u64, now: u64) -> Option<u64> {
    (applied > 0).then(|| now.checked_sub(applied)).flatten()
}

#[cfg(test)]
mod metric_tests {
    use super::tunnel_age;
    #[test]
    fn runtime_age_does_not_invent_a_session_for_legacy_or_future_state() {
        assert_eq!(tunnel_age(100, 125), Some(25));
        assert_eq!(tunnel_age(0, 125), None);
        assert_eq!(tunnel_age(130, 125), None);
    }
}
