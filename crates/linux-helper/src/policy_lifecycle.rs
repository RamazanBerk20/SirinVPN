//! Version 7 connects are monitored independently of recovery and boot preferences.
use super::*;

impl RuntimeState {
    pub(super) fn for_policy(request: &TunnelConnectRequest) -> Self {
        Self {
            application_guard_verified: None,
            mtu: mtu::initial_mtu(request),
            mtu_sampled_at_unix: None,
            quality: None,
            endpoint_monitor: endpoints::EndpointMonitor::from_request(request),
            schema_version: if request.routing.mode == TunnelRoutingMode::SelectedApplications {
                5
            } else if request.endpoint_identity.is_some() {
                4
            } else {
                3
            },
            server_id: request.server_id,
            policy: request.policy,
            persistent_protection: false,
            reconnecting: true,
            has_connected: false,
            initial_attempts: 0,
            waiting_for_user: false,
            enforcement: None,
            observed_at_boot_seconds: None,
            applied_at_unix: 0,
            client_ipv6_address: request.client_ipv6_address,
            transport: request.transport,
            transport_fallback_enabled: !request.reconnect_candidates.is_empty(),
            routing: request.routing.clone(),
            dns_address: Some(request.dns_address),
        }
    }
}

impl<R: CommandRunner> LinuxNetworkHelper<R> {
    pub(super) fn connect_with_policy(
        &self,
        request: &TunnelConnectRequest,
    ) -> Result<LocalTunnelStatus, HelperError> {
        // Resolving a hostname before arming is limited to the explicit Connect operation.
        // Manual resume reuses the already resolved endpoint; no DNS exception is opened.
        let previous = if self.persistent_path().exists() {
            Some(self.read_persistent()?)
        } else {
            None
        };
        let mut prepared = request.clone();
        if prepared.endpoint_identity.is_some() {
            prepared.endpoint_dns_servers = self.endpoint_dns_servers();
        }
        let resolved_endpoints =
            self.resolve_endpoint_set(&prepared, previous.as_ref().map(|saved| saved.endpoint));
        let request = &prepared;
        let preferred = resolved_endpoints
            .iter()
            .find(|resolved| resolved.host == request.endpoint_host)
            .or_else(|| resolved_endpoints.first());
        let endpoint = if let Some(previous) = &previous {
            let state = self.read_state().ok();
            if state.as_ref().is_some_and(|s| !s.waiting_for_user)
                || previous.request.server_id != request.server_id
                || previous.request.server_public_key != request.server_public_key
                || previous.request.policy != request.policy
                || previous.request.routing != request.routing
            {
                return Err(HelperError::ActivePolicy);
            }
            preferred.map_or(previous.endpoint, |resolved| resolved.address)
        } else {
            match preferred {
                Some(endpoint) => endpoint.address,
                None => resolve_endpoint(&request.endpoint_host, request.endpoint_port)?,
            }
        };
        if let Some(resolved) = resolved_endpoints
            .iter()
            .find(|resolved| resolved.address == endpoint)
        {
            prepared.endpoint_host = resolved.host.clone();
        }
        let request = &prepared;
        let resolved_endpoints =
            if request.endpoint_identity.is_some() && resolved_endpoints.is_empty() {
                vec![endpoints::ResolvedEndpoint {
                    host: request.endpoint_host.clone(),
                    address: endpoint,
                }]
            } else {
                resolved_endpoints
            };
        {
            let _lock = self.lock_operations()?;
            self.ensure_ownership()?;
            // Check again under the operation lock: a concurrent Connect must not replace
            // another server's active device-wide policy.
            if self.state_path().exists() {
                let current = self.read_state()?;
                if !current.waiting_for_user
                    || current.server_id != request.server_id
                    || current.policy != request.policy
                    || current.routing != request.routing
                {
                    return Err(HelperError::ActivePolicy);
                }
            }
            self.write_persistent(&PersistentConnection {
                resolved_endpoints,
                schema_version: request.desired_schema(),
                request: request.clone(),
                endpoint,
                obfuscated_udp: None,
                tcp_fallback: None,
                extended_routing: None,
            })?;
            let mut state = RuntimeState::for_policy(request);
            self.write_state(&state)
                .map_err(|_| HelperError::NetworkOperationFailed)?;
            if request.connection_policy().kill_switch {
                if let Err(error) = self.apply_policy_guard(request, endpoint) {
                    state.waiting_for_user = true;
                    state.reconnecting = false;
                    self.observe_policy(&mut state, request, endpoint);
                    self.write_state(&state)
                        .map_err(|_| HelperError::NetworkOperationFailed)?;
                    return Err(error);
                }
            } else if !self.guard_is_absent()? {
                return Err(HelperError::ActivePolicy);
            }
        }
        // No cleanup path here removes the traffic block. Explicit Disconnect releases it.
        self.reconcile_persistent_once(false)?;
        if let Err(error) = self.start_policy_services(request.connection_policy()) {
            let _lock = self.lock_operations()?;
            let mut state = self.read_state()?;
            state.reconnecting = false;
            state.waiting_for_user = true;
            self.cleanup_tunnel_owned()?;
            self.observe_policy(&mut state, request, endpoint);
            self.write_state(&state)
                .map_err(|_| HelperError::NetworkOperationFailed)?;
            return Err(error);
        }
        self.status()
    }

    /// Used by the key-rotation transaction. It pauses recovery without releasing
    /// the kernel guard or changing the saved boot/session policy.
    pub fn pause_for_key_rotation(
        &self,
        server_id: ServerId,
    ) -> Result<LocalTunnelStatus, HelperError> {
        {
            let _lock = self.lock_operations()?;
            if !self.state_path().exists() {
                return Ok(disconnected_status());
            }
            let mut desired = self.read_persistent()?;
            let mut state = self.read_state()?;
            if state.server_id != server_id {
                return Err(HelperError::ActivePolicy);
            }
            if state.policy.is_none() {
                // Adopt an enabled legacy bundle without any firewall gap. Its former
                // recovery and boot decisions remain enabled in the versioned policy.
                let policy = desired.request.connection_policy();
                if !policy.kill_switch {
                    return Err(HelperError::ActivePolicy);
                }
                desired.request.policy = Some(policy);
                desired.request.persistent_protection = false;
                desired.request.schema_version = 7;
                desired.schema_version = 2;
                desired.obfuscated_udp = None;
                desired.tcp_fallback = None;
                desired.extended_routing = None;
                state.policy = Some(policy);
                state.persistent_protection = false;
                state.schema_version = 3;
                state.has_connected = !state.reconnecting;
                state.initial_attempts = 1;
                let request = current_persistent_request(&desired, Some(&state));
                self.apply_policy_guard(&request, desired.endpoint)?;
                self.write_persistent(&desired)?;
            }
            state.waiting_for_user = true;
            state.reconnecting = false;
            self.write_state(&state)
                .map_err(|_| HelperError::NetworkOperationFailed)?;
            self.cleanup_tunnel_owned()?;
            let request = current_persistent_request(&desired, Some(&state));
            self.observe_policy(&mut state, &request, desired.endpoint);
            self.write_state(&state)
                .map_err(|_| HelperError::NetworkOperationFailed)?;
        }
        self.status()
    }

    pub fn resume(&self, server_id: ServerId) -> Result<LocalTunnelStatus, HelperError> {
        let desired = self.read_persistent()?;
        let current = self.read_state()?;
        if desired.request.server_id != server_id
            || current.server_id != server_id
            || !current.waiting_for_user
            || desired.request.policy.is_none()
        {
            return Err(HelperError::ActivePolicy);
        }
        self.connect_with_policy(&desired.request)
    }

    fn start_policy_services(&self, policy: ConnectionPolicy) -> Result<(), HelperError> {
        let operation = if policy.connect_on_startup {
            "enable"
        } else {
            "disable"
        };
        self.runner
            .run("systemctl", &[operation, RECONNECT_UNIT], None)
            .map_err(|_| HelperError::NetworkOperationFailed)?;
        let operation = if policy.connect_on_startup && policy.kill_switch {
            "enable"
        } else {
            "disable"
        };
        self.runner
            .run("systemctl", &[operation, KILL_SWITCH_UNIT], None)
            .map_err(|_| HelperError::NetworkOperationFailed)?;
        // Fresh intent needs a fresh observer, even if the previous service is
        // still in its polling/backoff wait. This restarts no network interface.
        self.runner
            .run("systemctl", &["restart", RECONNECT_UNIT], None)
            .map_err(|_| HelperError::NetworkOperationFailed)
    }
}
