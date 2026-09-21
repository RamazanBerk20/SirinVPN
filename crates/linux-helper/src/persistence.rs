//! Persistence.

use super::*;

impl<R: CommandRunner> LinuxNetworkHelper<R> {
    pub fn restore_kill_switch(&self) -> Result<(), HelperError> {
        let _lock = self.lock_operations()?;
        let persistent = self.read_persistent()?;
        let runtime = self.read_state().ok();
        let request = current_persistent_request(&persistent, runtime.as_ref());
        if request.policy.is_some() {
            if request.connection_policy().connect_on_startup
                && request.connection_policy().kill_switch
            {
                self.apply_policy_guard(&request, persistent.endpoint)?;
            }
            Ok(())
        } else {
            self.apply_kill_switch(&request, persistent.endpoint)
        }
    }

    pub fn supervise(&self) -> Result<(), HelperError>
    where
        R: Sync,
    {
        use std::sync::atomic::{AtomicBool, Ordering};
        let stopped = AtomicBool::new(false);
        thread::scope(|scope| {
            scope.spawn(|| {
                while !stopped.load(Ordering::Acquire) {
                    let _ = self.measure_current_path();
                    for _ in 0..50 {
                        if stopped.load(Ordering::Acquire) {
                            break;
                        }
                        thread::sleep(Duration::from_millis(100));
                    }
                }
            });
            scope.spawn(|| {
                while !stopped.load(Ordering::Acquire) {
                    self.runner.optimize_session();
                    for _ in 0..10 {
                        if stopped.load(Ordering::Acquire) {
                            break;
                        }
                        thread::sleep(Duration::from_millis(100));
                    }
                }
            });
            let result = self.supervise_connection();
            stopped.store(true, Ordering::Release);
            if result.is_err() && !self.persistent_path().exists() && !self.state_path().exists() {
                // Disconnect can remove intent between the poll and locked read.
                Ok(())
            } else {
                result
            }
        })
    }

    fn supervise_connection(&self) -> Result<(), HelperError> {
        let mut reconnect_backoff = SUPERVISOR_POLL_SECONDS;
        let mut network_epoch = NetworkEpochTracker::default();
        loop {
            if !self.persistent_path().exists() {
                return Ok(());
            }
            let desired = self.read_persistent()?;
            if desired.request.policy.is_some()
                && !desired.request.connection_policy().connect_on_startup
                && !self.state_path().exists()
            {
                return Ok(());
            }
            let physical_route = self.physical_default_route_fingerprint();
            let observed_handshake = self.latest_handshake_timestamp();
            if let Some(physical_route) = physical_route {
                network_epoch.observe(physical_route, observed_handshake, now_unix());
            }
            match self.reconcile_persistent_once_with_context(true, network_epoch.context())? {
                ReconcileOutcome::Healthy => {
                    reconnect_backoff = SUPERVISOR_POLL_SECONDS;
                    thread::sleep(Duration::from_secs(SUPERVISOR_POLL_SECONDS));
                }
                ReconcileOutcome::AwaitingHandshake => {
                    if self.wait_for_network_or_handshake(
                        Duration::from_secs(SUPERVISOR_POLL_SECONDS),
                        physical_route,
                        (network_epoch.context().physical_route_available != Some(false))
                            .then_some(observed_handshake),
                    ) {
                        reconnect_backoff = SUPERVISOR_POLL_SECONDS;
                    }
                }
                ReconcileOutcome::ReconnectPending => {
                    reconnect_backoff = if self.wait_for_network_or_handshake(
                        Duration::from_secs(reconnect_backoff),
                        physical_route,
                        None,
                    ) {
                        SUPERVISOR_POLL_SECONDS
                    } else {
                        (reconnect_backoff.saturating_mul(2)).min(MAX_RECONNECT_BACKOFF_SECONDS)
                    };
                }
            }
        }
    }

    // ponytail: poll only during connection/recovery; use netlink notifications
    // if spawning route queries becomes a measurable cost on low-power devices.
    pub(super) fn wait_for_network_or_handshake(
        &self,
        timeout: Duration,
        route: Option<Option<u64>>,
        initial_handshake: Option<Option<u64>>,
    ) -> bool {
        // Compare with the observation BEFORE apply: the first handshake may
        // already have arrived while configuring DNS or publishing state.
        let interval = Duration::from_millis(if initial_handshake.is_some() {
            100
        } else {
            250
        });
        let started = std::time::Instant::now();
        while started.elapsed() < timeout {
            thread::sleep(interval.min(timeout.saturating_sub(started.elapsed())));
            if !self.persistent_path().exists() {
                return false;
            }
            let current = self.physical_default_route_fingerprint();
            if current.is_some() && current != route {
                return true;
            }
            if initial_handshake.is_some_and(|initial| self.latest_handshake_timestamp() != initial)
            {
                return false;
            }
        }
        false
    }

    pub(super) fn reconcile_persistent_once(
        &self,
        check_handshake: bool,
    ) -> Result<ReconcileOutcome, HelperError> {
        self.reconcile_persistent_once_with_context(check_handshake, SupervisorContext::default())
    }

    pub(super) fn reconcile_persistent_once_with_context(
        &self,
        check_handshake: bool,
        supervisor: SupervisorContext,
    ) -> Result<ReconcileOutcome, HelperError> {
        let _lock = self.lock_operations()?;
        let persistent = self.read_persistent()?;
        let runtime = if self.state_path().exists() {
            Some(self.read_state()?)
        } else {
            None
        };
        if persistent.request.policy.is_some() {
            return self.reconcile_policy(&persistent, runtime, check_handshake, supervisor);
        }
        let current_request = current_persistent_request(&persistent, runtime.as_ref());
        let transport_fallback_enabled = !persistent.request.reconnect_candidates.is_empty();
        if !self.kill_switch_exists() {
            self.apply_kill_switch(&current_request, persistent.endpoint)?;
        }

        if self.state_path().exists() {
            fs::set_permissions(self.state_path(), fs::Permissions::from_mode(0o644))
                .map_err(|_| HelperError::NetworkOperationFailed)?;
        }
        if check_handshake && supervisor.physical_route_available == Some(false) {
            return Ok(ReconcileOutcome::AwaitingHandshake);
        }
        let now = now_unix();
        let configuration_present = runtime.as_ref().is_some_and(|state| {
            state.server_id == current_request.server_id
                && state.transport == current_request.transport
                && state.routing == current_request.routing
        }) && self.tunnel_configuration_exists(&current_request);
        if configuration_present {
            if !check_handshake {
                return Ok(ReconcileOutcome::AwaitingHandshake);
            }
            let latest_handshake = self.latest_handshake_timestamp();
            if established_handshake_is_healthy(latest_handshake, now, supervisor.route_transition)
            {
                if runtime.as_ref().is_some_and(|state| {
                    state.reconnecting
                        || state.transport_fallback_enabled != transport_fallback_enabled
                }) {
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
                        server_id: current_request.server_id,
                        persistent_protection: true,
                        reconnecting: false,
                        applied_at_unix: runtime
                            .as_ref()
                            .map_or_else(now_unix, |state| state.applied_at_unix),
                        client_ipv6_address: current_request.client_ipv6_address,
                        transport: current_request.transport,
                        transport_fallback_enabled,
                        routing: current_request.routing.clone(),
                        dns_address: current_request
                            .routing
                            .allow_lan
                            .then_some(current_request.dns_address),
                    })
                    .map_err(|_| HelperError::NetworkOperationFailed)?;
                }
                return Ok(ReconcileOutcome::Healthy);
            }
            if supervisor.route_transition.is_some_and(|transition| {
                now.saturating_sub(transition.detected_at_unix) < HANDSHAKE_GRACE_SECONDS
            }) {
                return Ok(ReconcileOutcome::AwaitingHandshake);
            }
        }
        let applied_at = runtime.as_ref().map_or(0, |state| state.applied_at_unix);
        let current_attempt_is_in_grace = runtime.as_ref().is_some_and(|state| {
            state.server_id == current_request.server_id
                && state.transport == current_request.transport
                && state.routing == current_request.routing
                && now.saturating_sub(applied_at) < HANDSHAKE_GRACE_SECONDS
        });
        if check_handshake && current_attempt_is_in_grace {
            return Ok(ReconcileOutcome::AwaitingHandshake);
        }

        let next_request = if check_handshake
            && runtime.as_ref().is_some_and(|state| {
                state.server_id == current_request.server_id
                    && state.transport == current_request.transport
                    && state.routing == current_request.routing
            }) {
            next_persistent_request(&persistent, current_request.transport)
        } else {
            current_request.clone()
        };
        self.cleanup_tunnel_owned()?;
        if next_request.transport != current_request.transport {
            self.apply_kill_switch(&next_request, persistent.endpoint)?;
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
            server_id: next_request.server_id,
            persistent_protection: true,
            reconnecting: true,
            applied_at_unix: now,
            client_ipv6_address: next_request.client_ipv6_address,
            transport: next_request.transport,
            transport_fallback_enabled,
            routing: next_request.routing.clone(),
            dns_address: next_request
                .routing
                .allow_lan
                .then_some(next_request.dns_address),
        })
        .map_err(|_| HelperError::NetworkOperationFailed)?;
        if self
            .apply(&next_request, persistent.endpoint, true)
            .is_err()
        {
            self.cleanup_tunnel_owned()?;
            return Ok(ReconcileOutcome::ReconnectPending);
        }
        Ok(ReconcileOutcome::AwaitingHandshake)
    }

    pub(super) fn start_persistent_services(&self) -> Result<(), HelperError> {
        self.runner
            .run(
                "systemctl",
                &["enable", KILL_SWITCH_UNIT, RECONNECT_UNIT],
                None,
            )
            .map_err(|_| HelperError::PersistentProtectionUnavailable)?;
        self.runner
            .run("systemctl", &["restart", RECONNECT_UNIT], None)
            .map_err(|_| HelperError::PersistentProtectionUnavailable)
    }

    pub(super) fn persistent_path(&self) -> PathBuf {
        self.persistent_directory.join("desired-connection.json")
    }

    pub(super) fn lock_operations(&self) -> Result<fs::File, HelperError> {
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o755)
            .create(&self.runtime_directory)
            .map_err(|_| HelperError::NetworkOperationFailed)?;
        fs::set_permissions(&self.runtime_directory, fs::Permissions::from_mode(0o755))
            .map_err(|_| HelperError::NetworkOperationFailed)?;
        let lock = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(self.runtime_directory.join("operation.lock"))
            .map_err(|_| HelperError::NetworkOperationFailed)?;
        lock.lock_exclusive()
            .map_err(|_| HelperError::NetworkOperationFailed)?;
        Ok(lock)
    }
}
