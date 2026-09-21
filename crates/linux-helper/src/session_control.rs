//! Explicit session operations retain the acknowledged policy and the kernel hook.
use super::*;

impl<R: CommandRunner> LinuxNetworkHelper<R> {
    /// Stop attempts without releasing protection or changing saved boot intent.
    pub fn pause_session(&self, server_id: ServerId) -> Result<LocalTunnelStatus, HelperError> {
        self.pause_for_key_rotation(server_id)
    }

    /// Restart from the root-owned, acknowledged configuration, never UI drafts.
    pub fn reconnect_session(&self, server_id: ServerId) -> Result<LocalTunnelStatus, HelperError> {
        let desired = self.read_persistent()?;
        if desired.request.server_id != server_id || desired.request.policy.is_none() {
            return Err(HelperError::ActivePolicy);
        }
        self.replace_session(server_id, &desired.request, desired.endpoint)
    }

    /// Name resolution happens through the existing routing policy before teardown.
    /// A failed lookup never opens an unprotected DNS exception.
    pub fn switch_session(
        &self,
        change: &SwitchConnectRequest,
    ) -> Result<LocalTunnelStatus, HelperError> {
        validate_request(&change.request)?;
        if change.request.server_id == change.expected_server_id || change.request.policy.is_none()
        {
            return Err(HelperError::ActivePolicy);
        }
        let endpoint =
            resolve_endpoint(&change.request.endpoint_host, change.request.endpoint_port)?;
        self.replace_session(change.expected_server_id, &change.request, endpoint)
    }

    fn replace_session(
        &self,
        expected: ServerId,
        next: &TunnelConnectRequest,
        endpoint: IpAddr,
    ) -> Result<LocalTunnelStatus, HelperError> {
        {
            let _lock = self.lock_operations()?;
            self.ensure_ownership()?;
            let desired = self.read_persistent()?;
            let mut current = self.read_state()?;
            // Check again after resolution/authorization and under the supervisor's lock.
            // Routing and all three policy decisions are device-wide for this session.
            if current.server_id != expected
                || desired.request.server_id != expected
                || current.policy.is_none()
                || current.policy != next.policy
                || current.routing != next.routing
                || desired.request.policy != next.policy
                || (next.server_id == expected && desired.request != *next)
            {
                return Err(HelperError::ActivePolicy);
            }
            let old = current_persistent_request(&desired, Some(&current));
            if next.connection_policy().kill_switch {
                if !self.guard_is_verified(&old, desired.endpoint) {
                    self.apply_policy_guard(&old, desired.endpoint)?;
                }
            } else if !self.guard_is_absent()? {
                return Err(HelperError::ActivePolicy);
            }
            // An interrupted transaction leaves explicit manual recovery, never an
            // unprotected cleanup or an automatic retry using half-written intent.
            current.waiting_for_user = true;
            current.reconnecting = false;
            self.write_state(&current)
                .map_err(|_| HelperError::NetworkOperationFailed)?;
            if next.connection_policy().kill_switch {
                self.apply_policy_guard(next, endpoint)?;
            }
            self.cleanup_tunnel_owned()?;
            if expected != next.server_id {
                // Processes from the previous server keep an isolated, disconnected
                // namespace. A launch on the new server creates a fresh namespace.
                self.destroy_applications()?;
            }
            let replacement = PersistentConnection {
                resolved_endpoints: self.resolve_endpoint_set(next, Some(endpoint)),
                schema_version: next.desired_schema(),
                request: next.clone(),
                endpoint,
                obfuscated_udp: None,
                tcp_fallback: None,
                extended_routing: None,
            };
            self.write_persistent(&replacement)?;
            let state = RuntimeState::for_policy(next);
            self.write_state(&state)
                .map_err(|_| HelperError::NetworkOperationFailed)?;
            self.reconcile_policy(
                &replacement,
                Some(state),
                false,
                SupervisorContext::default(),
            )?;
        }
        // Observe the replacement immediately, without the old monitor's pending
        // poll/backoff delay. Restarting supervision never releases the guard.
        self.runner
            .run("systemctl", &["restart", RECONNECT_UNIT], None)
            .map_err(|_| HelperError::NetworkOperationFailed)?;
        self.status()
    }

    /// A tray confirmation names a specific active server. A stale confirmation
    /// must not disconnect a different connection that appeared in the meantime.
    pub fn disconnect_session(&self, expected: ServerId) -> Result<LocalTunnelStatus, HelperError> {
        let _lock = self.lock_operations()?;
        self.ensure_ownership()?;
        if self.read_state()?.server_id != expected {
            return Err(HelperError::ActivePolicy);
        }
        self.guard_is_absent()?;
        self.cleanup_all_owned()?;
        if !self.guard_is_absent()?
            || self
                .runner
                .succeeds("ip", &["link", "show", INTERFACE_NAME])
        {
            return Err(HelperError::NetworkOperationFailed);
        }
        remove_file_if_exists(&self.state_path())
            .map_err(|_| HelperError::NetworkOperationFailed)?;
        remove_file_if_exists(&self.persistent_path())
            .map_err(|_| HelperError::NetworkOperationFailed)?;
        self.runner
            .run(
                "systemctl",
                &["disable", KILL_SWITCH_UNIT, RECONNECT_UNIT],
                None,
            )
            .map_err(|_| HelperError::NetworkOperationFailed)?;
        // With intent deleted the monitor exits on its next pass. Do not stop it
        // outside this lock: that could stop a newly started, different session.
        Ok(disconnected_status())
    }
}
