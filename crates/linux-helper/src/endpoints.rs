//! Current signed endpoint state and bounded recovery across its known addresses.
use super::*;
use sirinvpn_protocol::{EndpointIdentity, EndpointTransitionResponse};
use sirinvpn_transport::TransportEngine;
pub(super) use sirinvpn_tunnel_model::hosts;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ResolvedEndpoint {
    pub host: String,
    pub address: IpAddr,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct EndpointMonitor {
    checked_at: u64,
    idle_counter: Option<(u64, u64)>,
    pending: Option<EndpointTransitionResponse>,
    #[serde(default)]
    pending_since: Option<u64>,
    pub accepted: Option<EndpointTransitionResponse>,
    publication_generation: Option<u64>,
}

impl EndpointMonitor {
    pub(super) fn from_request(request: &TunnelConnectRequest) -> Option<Self> {
        request.endpoint_identity.as_ref().map(|_| Self {
            accepted: request.endpoint_checkpoint.clone(),
            ..Self::default()
        })
    }
    pub(super) fn valid(&self, server_id: ServerId) -> bool {
        self.pending.iter().chain(self.accepted.iter()).all(|head| {
            head.claims.server_id == server_id
                && sirinvpn_core::DecodedEndpointTransition::from_response(head.clone()).is_ok()
        })
    }
    fn idle(&mut self, bytes: Option<u64>, now: u64) -> bool {
        let Some(bytes) = bytes else {
            self.idle_counter = None;
            return false;
        };
        self.idle_counter
            .replace((now, bytes))
            .is_some_and(|(at, previous)| {
                now.saturating_sub(at) >= 10
                    && now.saturating_sub(at) <= 90
                    && bytes >= previous
                    && bytes - previous <= 32 * 1024
            })
    }
}

pub(super) fn validate_resolved(persistent: &PersistentConnection) -> bool {
    if persistent.request.endpoint_identity.is_none() {
        return persistent.resolved_endpoints.is_empty();
    }
    let known = persistent
        .request
        .endpoint_identity
        .as_ref()
        .expect("checked identity");
    !persistent.resolved_endpoints.is_empty()
        && persistent.resolved_endpoints.len() <= 9
        && persistent
            .resolved_endpoints
            .iter()
            .enumerate()
            .all(|(index, endpoint)| {
                hosts(known).any(|host| host == endpoint.host)
                    && !endpoint.address.is_unspecified()
                    && !endpoint.address.is_multicast()
                    && !persistent.resolved_endpoints[..index].contains(endpoint)
            })
        && persistent.resolved_endpoints.iter().any(|endpoint| {
            endpoint.host == persistent.request.endpoint_host
                && endpoint.address == persistent.endpoint
        })
}

impl<R: CommandRunner> LinuxNetworkHelper<R> {
    pub(super) fn endpoint_dns_servers(&self) -> Vec<SocketAddr> {
        self.runner
            .output_with_timeout("resolvectl", &["dns"], Duration::from_secs(1))
            .ok()
            .map_or_else(Vec::new, |output| {
                endpoint_resolution::configured_resolvers(&output)
            })
    }

    pub(super) fn resolve_endpoint_set(
        &self,
        request: &TunnelConnectRequest,
        retained: Option<IpAddr>,
    ) -> Vec<ResolvedEndpoint> {
        let Some(known) = &request.endpoint_identity else {
            return Vec::new();
        };
        let mut resolved = Vec::new();
        // Keep a stable order across retries, including when the active host is
        // an alternate. Moving it to the front can starve a third address.
        let hosts = hosts(known).collect::<Vec<_>>();
        let addresses = self
            .runner
            .endpoint_addresses_for_hosts(&hosts, &request.endpoint_dns_servers);
        for (host, addresses) in hosts.into_iter().zip(addresses) {
            for address in addresses.into_iter().take(2) {
                let endpoint = ResolvedEndpoint {
                    host: host.to_owned(),
                    address,
                };
                if !endpoint.address.is_unspecified()
                    && !endpoint.address.is_multicast()
                    && !resolved.contains(&endpoint)
                {
                    resolved.push(endpoint);
                }
            }
        }
        if let Some(address) = retained {
            let endpoint = ResolvedEndpoint {
                host: request.endpoint_host.clone(),
                address,
            };
            if !resolved.contains(&endpoint) {
                resolved.push(endpoint);
            }
        }
        resolved
    }

    /// The caller has verified the existing guard and holds the operation lock.
    /// Paused sessions and established sessions with recovery disabled do not call
    /// this method. A healthy session waits for a quiet interval before handoff.
    pub(super) fn inspect_endpoint_checkpoint(
        &self,
        desired: &mut PersistentConnection,
        state: &mut RuntimeState,
        healthy: bool,
    ) -> Result<Option<ReconcileOutcome>, HelperError> {
        let Some(known) = desired.request.endpoint_identity.clone() else {
            return Ok(None);
        };
        if state.waiting_for_user
            || (!desired.request.connection_policy().automatic_reconnect
                && (state.has_connected || state.initial_attempts > 0))
        {
            return Ok(None);
        }
        let now = now_unix();
        let current_request = current_persistent_request(desired, Some(state));
        let monitor = state
            .endpoint_monitor
            .get_or_insert_with(EndpointMonitor::default);
        let idle = if healthy {
            monitor.idle(
                self.runner
                    .output("wg", &["show", INTERFACE_NAME, "transfer"])
                    .ok()
                    .and_then(|bytes| quality::transfer_counter(&bytes)),
                now,
            )
        } else {
            true
        };
        if now.saturating_sub(monitor.checked_at) >= 60 || monitor.checked_at > now {
            monitor.checked_at = now;
            if let Ok(Some(head)) = self.runner.endpoint_checkpoint(
                &known,
                &desired.request.private_key,
                desired.endpoint,
            ) {
                let newer = sirinvpn_core::verify_endpoint_checkpoint(&known, &head).is_ok();
                let current = sirinvpn_core::current_checkpoint_matches(&known, &head);
                if newer || current {
                    if newer {
                        if monitor.pending.as_ref() != Some(&head)
                            || monitor.pending_since.is_none_or(|since| since > now)
                        {
                            monitor.pending_since = Some(now);
                        }
                        monitor.pending = Some(head.clone());
                    } else {
                        monitor.accepted = Some(head.clone());
                    }
                    if desired.request.endpoint_publication_enabled
                        && monitor.publication_generation != Some(head.claims.generation)
                        && self.publish_checkpoint_to_source(
                            &current_request,
                            desired.endpoint,
                            &known,
                            &head,
                        )?
                    {
                        monitor.publication_generation = Some(head.claims.generation);
                    }
                }
            }
        }
        let handoff_due = monitor
            .pending_since
            .is_some_and(|since| now.saturating_sub(since) >= 60);
        if healthy && !idle && !handoff_due {
            return Ok(None);
        }
        let Some(head) = monitor.pending.clone() else {
            return Ok(None);
        };
        self.activate_endpoint_checkpoint(desired, state, head)
    }

    fn activate_endpoint_checkpoint(
        &self,
        desired: &PersistentConnection,
        state: &mut RuntimeState,
        head: EndpointTransitionResponse,
    ) -> Result<Option<ReconcileOutcome>, HelperError> {
        let known = desired
            .request
            .endpoint_identity
            .as_ref()
            .ok_or(HelperError::InvalidState)?;
        let updated = sirinvpn_core::verify_endpoint_checkpoint(known, &head)
            .map_err(|_| HelperError::InvalidState)?;
        let mut replacement = desired.clone();
        let current = current_persistent_request(desired, Some(state));
        let kinds = if desired.request.reconnect_candidates.is_empty() {
            vec![current.transport]
        } else {
            desired
                .request
                .reconnect_candidates
                .iter()
                .map(|candidate| candidate.transport)
                .collect()
        };
        let mut selections = kinds
            .into_iter()
            .filter_map(|kind| {
                TransportEngine
                    .select_descriptor(&updated.descriptor, kind)
                    .ok()
            })
            .collect::<Vec<_>>();
        if selections.is_empty() {
            return Ok(None);
        }
        if let Some(sirinvpn_protocol::MtuPolicy::Manual { value }) = current.mtu_policy {
            for selection in &mut selections {
                selection.mtu = value;
            }
        }
        let selection = selections
            .iter()
            .find(|selection| selection.kind == current.transport)
            .unwrap_or(&selections[0]);
        replacement.request = request_with_selection(&current, selection);
        replacement.request.endpoint_identity = Some(updated);
        replacement.request.endpoint_checkpoint = Some(head.clone());
        // Rotate the plan so the requested transport remains its first member.
        let offset = selections
            .iter()
            .position(|item| item.kind == selection.kind)
            .unwrap_or(0);
        selections.rotate_left(offset);
        replacement.request.reconnect_candidates = policy_transport_candidates(&selections);
        replacement.request.client_ipv6_address = if current.client_address.octets()[3] < 224
            && replacement
                .request
                .endpoint_identity
                .as_ref()
                .is_some_and(|identity| identity.descriptor.ipv6_tunnel_enabled)
        {
            sirinvpn_protocol::ipv6_tunnel_address(current.server_id, current.client_address)
        } else {
            None
        };
        if validate_request(&replacement.request).is_err() {
            return Ok(None);
        }
        let same_host = hosts(
            replacement
                .request
                .endpoint_identity
                .as_ref()
                .expect("verified identity"),
        )
        .any(|host| host == current.endpoint_host);
        if same_host {
            replacement.request.endpoint_host = current.endpoint_host.clone();
        }
        replacement.resolved_endpoints =
            self.resolve_endpoint_set(&replacement.request, same_host.then_some(desired.endpoint));
        let Some(endpoint) = replacement.resolved_endpoints.first().cloned() else {
            return Ok(None);
        };
        replacement.request.endpoint_host = endpoint.host;
        replacement.endpoint = endpoint.address;
        replacement.schema_version = replacement.request.desired_schema();
        self.apply_endpoint_replacement(desired, replacement, state, head)?;
        Ok(Some(ReconcileOutcome::AwaitingHandshake))
    }

    pub fn apply_endpoint_checkpoint(
        &self,
        head: &EndpointTransitionResponse,
    ) -> Result<LocalTunnelStatus, HelperError> {
        {
            let _lock = self.lock_operations()?;
            self.ensure_ownership()?;
            let desired = self.read_persistent()?;
            let mut state = self.read_state()?;
            let known = desired
                .request
                .endpoint_identity
                .as_ref()
                .ok_or(HelperError::InvalidState)?;
            if state.server_id != head.claims.server_id
                || state.server_id != desired.request.server_id
            {
                return Err(HelperError::ActivePolicy);
            }
            let request = current_persistent_request(&desired, Some(&state));
            if request.connection_policy().kill_switch {
                self.apply_policy_guard(&request, desired.endpoint)?;
            } else if !self.guard_is_absent()? {
                return Err(HelperError::ActivePolicy);
            }
            if !sirinvpn_core::current_checkpoint_matches(known, head)
                && self
                    .activate_endpoint_checkpoint(&desired, &mut state, head.clone())?
                    .is_none()
            {
                return Err(HelperError::InvalidConfiguration(
                    "the checkpoint has no usable transport for this connection".into(),
                ));
            }
        }
        self.status()
    }

    pub fn publish_endpoint_checkpoint(
        &self,
        head: &EndpointTransitionResponse,
    ) -> Result<LocalTunnelStatus, HelperError> {
        {
            let _lock = self.lock_operations()?;
            self.ensure_ownership()?;
            let desired = self.read_persistent()?;
            let mut state = self.read_state()?;
            let known = desired
                .request
                .endpoint_identity
                .as_ref()
                .ok_or(HelperError::InvalidState)?;
            if state.server_id != desired.request.server_id
                || !desired.request.endpoint_publication_enabled
                || (sirinvpn_core::verify_endpoint_checkpoint(known, head).is_err()
                    && !sirinvpn_core::current_checkpoint_matches(known, head))
            {
                return Err(HelperError::InvalidState);
            }
            let request = current_persistent_request(&desired, Some(&state));
            if request.connection_policy().kill_switch {
                self.apply_policy_guard(&request, desired.endpoint)?;
            } else if !self.guard_is_absent()? {
                return Err(HelperError::ActivePolicy);
            }
            if !self.publish_checkpoint_to_source(&request, desired.endpoint, known, head)? {
                return Err(HelperError::NetworkOperationFailed);
            }
            state
                .endpoint_monitor
                .get_or_insert_with(EndpointMonitor::default)
                .publication_generation = Some(head.claims.generation);
            self.write_state(&state)
                .map_err(|_| HelperError::NetworkOperationFailed)?;
        }
        self.status()
    }

    fn publish_checkpoint_to_source(
        &self,
        request: &TunnelConnectRequest,
        endpoint: IpAddr,
        known: &EndpointIdentity,
        head: &EndpointTransitionResponse,
    ) -> Result<bool, HelperError> {
        let Some(previous) = &head.claims.previous_transports else {
            return Ok(false);
        };
        if previous.endpoint.host == head.claims.endpoint.host {
            return Ok(true);
        }
        let Some(tls) = &previous.tls_like else {
            return Ok(false);
        };
        let port = previous.endpoint_discovery_port.unwrap_or(tls.port);
        let addresses = self
            .runner
            .endpoint_addresses(&previous.endpoint.host, &request.endpoint_dns_servers)
            .into_iter()
            .filter(|ip| !ip.is_unspecified() && !ip.is_multicast())
            .take(2)
            .collect::<Vec<_>>();
        if addresses.is_empty() {
            return Ok(false);
        }
        let controls = addresses
            .iter()
            .map(|ip| SocketAddr::new(*ip, port))
            .collect::<Vec<_>>();
        if request.connection_policy().kill_switch {
            self.apply_policy_guard_with_controls(request, endpoint, &controls)?;
        }
        let accepted = addresses.into_iter().any(|address| {
            self.runner
                .offer_endpoint_checkpoint(known, head, &request.private_key, address)
                .unwrap_or(false)
        });
        // The operation lock excludes other mutations. Remove the temporary,
        // marked TCP allowances even when the source was unavailable or refused.
        if request.connection_policy().kill_switch {
            self.apply_policy_guard(request, endpoint)?;
        }
        Ok(accepted)
    }

    fn apply_endpoint_replacement(
        &self,
        previous: &PersistentConnection,
        replacement: PersistentConnection,
        state: &mut RuntimeState,
        head: EndpointTransitionResponse,
    ) -> Result<(), HelperError> {
        let request = &replacement.request;
        let policy = request.connection_policy();
        if policy.kill_switch {
            self.apply_policy_guard(request, replacement.endpoint)?;
        }
        if let Err(error) = self.write_persistent(&replacement) {
            if policy.kill_switch {
                let _ = self.apply_policy_guard(
                    &current_persistent_request(previous, Some(state)),
                    previous.endpoint,
                );
            }
            return Err(error);
        }
        let previous_state = state.clone();
        state.transport = request.transport;
        state.applied_at_unix = now_unix();
        state.initial_attempts = 1;
        state.reconnecting = !state.waiting_for_user;
        state.mtu = mtu::initial_mtu(request);
        state.mtu_sampled_at_unix = None;
        state.client_ipv6_address = request.client_ipv6_address;
        state.quality = None;
        let monitor = state
            .endpoint_monitor
            .get_or_insert_with(EndpointMonitor::default);
        monitor.pending = None;
        monitor.pending_since = None;
        monitor.accepted = Some(head);
        if self.write_state(state).is_err() {
            *state = previous_state;
            if self.write_persistent(previous).is_ok() && policy.kill_switch {
                let _ = self.apply_policy_guard(
                    &current_persistent_request(previous, Some(state)),
                    previous.endpoint,
                );
            }
            return Err(HelperError::NetworkOperationFailed);
        }
        self.cleanup_tunnel_owned()?;
        if !state.waiting_for_user
            && self
                .apply(request, replacement.endpoint, policy.kill_switch)
                .is_err()
        {
            self.cleanup_tunnel_owned()?;
        }
        self.observe_policy(state, request, replacement.endpoint);
        self.write_state(state)
            .map_err(|_| HelperError::NetworkOperationFailed)
    }

    /// A complete transport cycle advances to the next known address. DNS is
    /// refreshed through the scoped sockets before another recovery cycle.
    pub(super) fn next_endpoint(
        &self,
        desired: &mut PersistentConnection,
        state: &RuntimeState,
    ) -> Result<(), HelperError> {
        if desired.request.endpoint_identity.is_none() {
            return Ok(());
        }
        if state.initial_attempts == 0
            || desired
                .request
                .reconnect_candidates
                .last()
                .is_some_and(|last| last.transport != state.transport)
        {
            return Ok(());
        }
        let mut replacement = desired.clone();
        let servers = self.endpoint_dns_servers();
        if !servers.is_empty() {
            replacement.request.endpoint_dns_servers = servers;
        }
        if replacement.request.connection_policy().kill_switch {
            self.apply_policy_guard(
                &current_persistent_request(&replacement, Some(state)),
                replacement.endpoint,
            )?;
        }
        let fresh = self.resolve_endpoint_set(&replacement.request, Some(desired.endpoint));
        if !fresh.is_empty() {
            replacement.resolved_endpoints = fresh;
        }
        if replacement.resolved_endpoints.len() > 1 {
            let index = replacement
                .resolved_endpoints
                .iter()
                .position(|endpoint| {
                    endpoint.address == desired.endpoint
                        && endpoint.host == desired.request.endpoint_host
                })
                .unwrap_or(0);
            let endpoint =
                &replacement.resolved_endpoints[(index + 1) % replacement.resolved_endpoints.len()];
            replacement.endpoint = endpoint.address;
            replacement.request.endpoint_host = endpoint.host.clone();
        }
        // The next call replaces the active transport allowance before teardown.
        *desired = replacement;
        Ok(())
    }
}

fn request_with_selection(
    base: &TunnelConnectRequest,
    selection: &TransportSelection,
) -> TunnelConnectRequest {
    let mut next = base.clone();
    next.schema_version = if next.routing.mode == TunnelRoutingMode::SelectedApplications {
        11
    } else {
        10
    };
    next.endpoint_host = selection.network_endpoint.host.clone();
    next.endpoint_port = selection.network_endpoint.wireguard_port;
    next.transport = selection.kind;
    next.server_transport_public_key = selection.server_transport_public_key.clone();
    next.server_certificate_sha256 = selection.server_certificate_sha256.clone();
    next.https = selection.https.clone();
    next.mtu = selection.mtu;
    next
}
