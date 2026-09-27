//! Initial selection, recovery, and protection are separate decisions.
use super::*;

impl<R: CommandRunner> LinuxNetworkHelper<R> {
    // Called with the operation lock held by the common supervisor.
    pub(super) fn reconcile_policy(
        &self,
        desired: &PersistentConnection,
        runtime: Option<RuntimeState>,
        check_handshake: bool,
        supervisor: SupervisorContext,
    ) -> Result<ReconcileOutcome, HelperError> {
        let mut desired = desired.clone();
        let policy = desired.request.connection_policy();
        // /run disappears at reboot. A saved session is not permission to reconnect
        // or block at boot unless the separate startup preference is enabled.
        if runtime.is_none() && !policy.connect_on_startup {
            return Ok(ReconcileOutcome::Healthy);
        }
        let request = current_persistent_request(&desired, runtime.as_ref());
        let mut state = runtime.unwrap_or_else(|| RuntimeState::for_policy(&request));
        if state.server_id != request.server_id || state.policy != request.policy {
            return Err(HelperError::InvalidState);
        }
        if policy.kill_switch
            && !self.guard_is_verified(&request, desired.endpoint)
            && let Err(error) = self.apply_policy_guard(&request, desired.endpoint)
        {
            self.observe_policy(&mut state, &request, desired.endpoint);
            self.write_state(&state)
                .map_err(|_| HelperError::NetworkOperationFailed)?;
            return Err(error);
        }
        if !policy.kill_switch && !self.guard_is_absent()? {
            return Err(HelperError::ActivePolicy);
        }
        if state.waiting_for_user {
            self.observe_policy(&mut state, &request, desired.endpoint);
            self.write_state(&state)
                .map_err(|_| HelperError::NetworkOperationFailed)?;
            return Ok(ReconcileOutcome::Healthy);
        }
        let now = now_unix();
        if supervisor.physical_route_available == Some(false) {
            state.reconnecting = true;
            if let Some(quality) = state.quality.as_mut() {
                quality.health = Default::default();
            }
            self.observe_policy(&mut state, &request, desired.endpoint);
            self.write_state(&state)
                .map_err(|_| HelperError::NetworkOperationFailed)?;
            return Ok(ReconcileOutcome::AwaitingHandshake);
        }
        if let Some(changed) = supervisor.network_changed_at_unix {
            let quality = state.quality.get_or_insert_with(Default::default);
            if changed > quality.network_changed_at_unix {
                quality.network_changed_at_unix = changed;
                quality.health = Default::default();
                if let Some(mtu) = state.mtu.as_mut() {
                    mtu.outcome = sirinvpn_protocol::MtuProbeOutcome::Pending;
                    mtu.suggested = None;
                }
                state.mtu_sampled_at_unix = None;
            }
        }
        let present = self.tunnel_configuration_exists(&request);
        // The old observer may have applied newly saved intent before the
        // explicit Connect invocation acquires this lock. Do not apply it twice.
        if !check_handshake && present && state.initial_attempts > 0 {
            return Ok(ReconcileOutcome::AwaitingHandshake);
        }
        if present
            && state.has_connected
            && self
                .repair_carrier_endpoint(&request, desired.endpoint)
                .map_err(|_| HelperError::NetworkOperationFailed)?
        {
            let quality = state.quality.get_or_insert_with(Default::default);
            quality.generation = quality.generation.saturating_add(1);
            quality.health = Default::default();
        }
        let handshake_healthy = present
            && supervisor.physical_route_available != Some(false)
            && established_handshake_is_healthy(
                self.latest_handshake_timestamp(),
                now,
                supervisor.route_transition,
            );
        let confirmed_failure = state.quality.as_ref().is_some_and(|q| q.health.failed(now));
        let healthy = handshake_healthy && !confirmed_failure
            || present
                && !confirmed_failure
                && state
                    .quality
                    .as_ref()
                    .is_some_and(|q| q.health.receiving(now));
        if (state.has_connected
            || (state.initial_attempts > 0
                && now.saturating_sub(state.applied_at_unix) >= HANDSHAKE_GRACE_SECONDS))
            && supervisor.physical_route_available != Some(false)
            && let Some(outcome) =
                self.inspect_endpoint_checkpoint(&mut desired, &mut state, healthy)?
        {
            return Ok(outcome);
        }
        if check_handshake && healthy {
            state.has_connected = true;
            state.reconnecting = false;
            self.observe_policy(&mut state, &request, desired.endpoint);
            self.write_state(&state)
                .map_err(|_| HelperError::NetworkOperationFailed)?;
            return Ok(ReconcileOutcome::Healthy);
        }
        let grace = present
            && state.initial_attempts > 0
            && now.saturating_sub(state.applied_at_unix) < HANDSHAKE_GRACE_SECONDS;
        let transition_grace = present
            && supervisor
                .route_transition
                .is_some_and(|t| now.saturating_sub(t.detected_at_unix) < HANDSHAKE_GRACE_SECONDS);
        if check_handshake && (grace || transition_grace) {
            state.reconnecting = true;
            self.observe_policy(&mut state, &request, desired.endpoint);
            self.write_state(&state)
                .map_err(|_| HelperError::NetworkOperationFailed)?;
            return Ok(ReconcileOutcome::AwaitingHandshake);
        }
        // An old handshake is suspicion, not proof of a broken established path.
        // Measurement runs outside this lock and requires repeated failed checks.
        if check_handshake && state.has_connected && present && !confirmed_failure {
            self.observe_policy(&mut state, &request, desired.endpoint);
            self.write_state(&state)
                .map_err(|_| HelperError::NetworkOperationFailed)?;
            return Ok(ReconcileOutcome::AwaitingHandshake);
        }
        let plan_length = desired.request.reconnect_candidates.len().max(1)
            * desired.resolved_endpoints.len().max(1);
        let initial_selection_remaining =
            !state.has_connected && usize::from(state.initial_attempts) < plan_length;
        if !initial_selection_remaining && !policy.automatic_reconnect {
            self.cleanup_tunnel_owned()?; // deliberately retains the guard
            state.waiting_for_user = true;
            state.reconnecting = false;
            self.observe_policy(&mut state, &request, desired.endpoint);
            self.write_state(&state)
                .map_err(|_| HelperError::NetworkOperationFailed)?;
            return Ok(ReconcileOutcome::Healthy);
        }
        if supervisor.physical_route_available == Some(false) {
            state.reconnecting = true;
            self.observe_policy(&mut state, &request, desired.endpoint);
            self.write_state(&state)
                .map_err(|_| HelperError::NetworkOperationFailed)?;
            return Ok(ReconcileOutcome::AwaitingHandshake);
        }
        if state.has_connected && present && confirmed_failure {
            // Multiple advertised carriers can share a blocked port (TLS/raw TCP).
            // Try the bounded remaining plan before replacing a live interface.
            let mut candidate = state.transport;
            for _ in 1..desired.request.reconnect_candidates.len() {
                let next = next_persistent_request(&desired, candidate);
                candidate = next.transport;
                match self.change_quality_transport(&desired, &next, &mut state) {
                    Ok(outcome) => {
                        state
                            .quality
                            .get_or_insert_with(Default::default)
                            .status
                            .last_switch_reason =
                            Some(sirinvpn_protocol::TransportSwitchReason::ConfirmedFailure);
                        self.write_state(&state)
                            .map_err(|_| HelperError::NetworkOperationFailed)?;
                        return Ok(outcome);
                    }
                    Err(HelperError::NetworkOperationFailed) => {
                        // Never advance with an unverified rollback. The old
                        // carrier may be unreachable, but its local path/guard
                        // must still be intact before another preparation.
                        if !self.carrier_endpoint_matches(&request, desired.endpoint)
                            || !self.tunnel_configuration_exists(&request)
                            || (policy.kill_switch
                                && !self.guard_is_verified(&request, desired.endpoint))
                        {
                            return Err(HelperError::NetworkOperationFailed);
                        }
                    }
                    Err(error) => return Err(error),
                }
            }
        }
        self.next_endpoint(&mut desired, &state)?;
        let next = if state.initial_attempts > 0 {
            next_persistent_request(&desired, state.transport)
        } else {
            request.clone()
        };
        // Update the endpoint allowance atomically while the old tunnel still exists.
        // Neither routing teardown nor relay restart removes the independent guard.
        if policy.kill_switch {
            self.apply_policy_guard(&next, desired.endpoint)?;
        }
        self.write_persistent(&desired)?;
        self.cleanup_tunnel_owned()?;
        state.transport = next.transport;
        state.quality = None;
        state.mtu = mtu::initial_mtu(&next);
        state.mtu_sampled_at_unix = None;
        state.initial_attempts = state.initial_attempts.saturating_add(1);
        state.applied_at_unix = now;
        state.reconnecting = true;
        self.observe_policy(&mut state, &next, desired.endpoint);
        self.write_state(&state)
            .map_err(|_| HelperError::NetworkOperationFailed)?;
        if self
            .apply(&next, desired.endpoint, policy.kill_switch)
            .is_err()
        {
            self.cleanup_tunnel_owned()?;
            self.observe_policy(&mut state, &next, desired.endpoint);
            self.write_state(&state)
                .map_err(|_| HelperError::NetworkOperationFailed)?;
            return Ok(ReconcileOutcome::ReconnectPending);
        }
        Ok(ReconcileOutcome::AwaitingHandshake)
    }
}
