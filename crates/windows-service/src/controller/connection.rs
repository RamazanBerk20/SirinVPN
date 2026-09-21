use super::*;
use crate::{carrier, network_plan};
use sirinvpn_tunnel_model::request_for_reconnect_candidate;

const HANDSHAKE_WINDOW: Duration = Duration::from_secs(12);
const STALE_HANDSHAKE: Duration = Duration::from_secs(240);
const PASS_WINDOW: Duration = Duration::from_secs(90);

impl Controller {
    pub(crate) async fn tick(&mut self) {
        self.operation_epoch = self.cancel.epoch.load(Ordering::SeqCst);
        if let Err(error) = self.tick_inner().await
            && error.kind() != io::ErrorKind::Interrupted
        {
            // No error path removes persistent protection. Stop further attempts
            // until the owner explicitly resumes after an enforcement/storage error.
            self.enforcement_failed = true;
            let _ = self.hold().await;
        }
        self.publish();
    }

    async fn tick_inner(&mut self) -> io::Result<()> {
        let Some(saved) = &self.saved else {
            return Ok(());
        };
        if saved.phase != SessionPhase::Held
            && saved.request.routing.mode
                == sirinvpn_tunnel_model::TunnelRoutingMode::SelectedApplications
            && !self.application_driver_ready()
        {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        if saved.phase == SessionPhase::Disconnecting {
            self.disconnect().await.map_err(|_| io::ErrorKind::Other)?;
            return Ok(());
        }
        if saved.phase == SessionPhase::Held {
            return Ok(());
        }
        if !self.firewall.verified()? {
            return Err(io::Error::other("owned policy changed"));
        }
        self.inspect_endpoints().await?;
        if self.cancel.epoch.load(Ordering::SeqCst) != self.operation_epoch {
            return Err(io::ErrorKind::Interrupted.into());
        }
        let mut connected = false;
        let mut failed = false;
        let mut failed_transport = None;
        let mut route_changed = false;
        if let Some(active) = self.active.as_mut() {
            let now = Instant::now();
            active.stats = active.adapter.statistics().ok();
            if let Some(stats) = active.stats {
                if stats.last_handshake_unix.is_some()
                    && stats.last_handshake_unix != active.handshake_marker
                {
                    active.handshake_marker = stats.last_handshake_unix;
                    active.handshake_seen = now;
                    if active.connected_at.is_none() {
                        active.connected_at = Some(now);
                        connected = true;
                    }
                }
            } else {
                failed = true;
            }
            failed |= active.carrier.as_ref().is_some_and(Carrier::finished);
            route_changed = network::underlay(
                active.endpoint.ip(),
                Some(unsafe { active.adapter.luid().Value }),
            )
            .map_or(true, |current| current != active.underlay);
            failed |= route_changed;
            failed |= if active.connected_at.is_some() {
                active.handshake_seen.elapsed() > STALE_HANDSHAKE
            } else {
                active.started.elapsed() > HANDSHAKE_WINDOW
            };
            if failed {
                failed_transport = Some(active.request.transport);
            }
        }
        if connected && !failed {
            self.saved.as_mut().expect("active saved session").phase = SessionPhase::Active;
            self.persist()?;
            self.had_connected = true;
            self.retry_passes = 0;
        }
        if failed {
            if route_changed {
                self.quality = crate::quality_plan::QualityMonitor::default();
                self.endpoints = endpoints::EndpointMonitor::default();
            }
            if let Some(previous) =
                failed_transport.and_then(|kind| self.quality.failed_trial(kind))
            {
                self.change_quality_transport(previous).await?;
                return Ok(());
            }
            self.close_guard()?;
            self.stop_active().await?;
            self.cleanup_routes()?;
            let automatic = self
                .saved
                .as_ref()
                .expect("saved session")
                .request
                .connection_policy()
                .automatic_reconnect;
            if self.had_connected && !automatic {
                self.hold().await.map_err(|_| io::ErrorKind::Other)?;
                return Ok(());
            }
            let saved = self.saved.as_mut().expect("saved session");
            saved.phase = SessionPhase::Connecting;
            self.persist()?;
            if self.had_connected {
                // First retry the current transport on the new physical path.
                self.had_connected = false;
                self.pass_started = Instant::now();
            } else {
                self.attempt_index += 1;
            }
            self.next_attempt = Instant::now() + Duration::from_secs(1);
        }
        if self.active.is_some() {
            self.inspect_measurements().await?;
            return Ok(());
        }
        if Instant::now() < self.next_attempt {
            return Ok(());
        }
        let count = self.attempt_count();
        if count == 0 || self.attempt_index >= count || self.pass_started.elapsed() >= PASS_WINDOW {
            if !self
                .saved
                .as_ref()
                .expect("saved session")
                .request
                .connection_policy()
                .automatic_reconnect
            {
                self.hold().await.map_err(|_| io::ErrorKind::Other)?;
                return Ok(());
            }
            // Re-resolve only this session's configured VPN names. A DNS outage
            // retains the last authenticated candidates, never a fallback resolver.
            let request = self.saved.as_ref().expect("saved session").request.clone();
            let fresh = self.resolve(&request).await?;
            if !fresh.is_empty() {
                self.saved.as_mut().expect("saved session").endpoints = fresh;
                self.persist()?;
            }
            self.retry_passes = self.retry_passes.saturating_add(1);
            let delay = 5u64
                .saturating_mul(1u64 << self.retry_passes.min(4).saturating_sub(1))
                .min(60);
            self.next_attempt = Instant::now() + Duration::from_secs(delay);
            self.pass_started = self.next_attempt;
            self.attempt_index = 0;
            return Ok(());
        }
        if self.start_attempt().await.is_err() {
            let kind =
                self.saved
                    .as_ref()
                    .and_then(|saved| {
                        saved.request.reconnect_candidates.get(
                            self.attempt_index % saved.request.reconnect_candidates.len().max(1),
                        )
                    })
                    .map(|candidate| candidate.transport);
            if let Some(previous) = kind.and_then(|kind| self.quality.failed_trial(kind)) {
                self.change_quality_transport(previous).await?;
                return Ok(());
            }
            self.close_guard()?;
            self.stop_active().await?;
            self.cleanup_routes()?;
            self.attempt_index += 1;
            self.next_attempt = Instant::now() + Duration::from_secs(1);
        }
        Ok(())
    }

    fn attempt_count(&self) -> usize {
        self.saved.as_ref().map_or(0, |saved| {
            saved.endpoints.len() * saved.request.reconnect_candidates.len().max(1)
        })
    }

    async fn start_attempt(&mut self) -> io::Result<()> {
        let saved = self.saved.as_ref().ok_or(io::ErrorKind::InvalidInput)?;
        let count = saved.request.reconnect_candidates.len().max(1);
        let endpoint = saved
            .endpoints
            .get(self.attempt_index / count)
            .ok_or(io::ErrorKind::InvalidInput)?;
        let mut request = if let Some(candidate) = saved
            .request
            .reconnect_candidates
            .get(self.attempt_index % count)
        {
            request_for_reconnect_candidate(&saved.request, candidate)
        } else {
            saved.request.clone()
        };
        request.endpoint_host = endpoint.host.clone();
        let endpoint = SocketAddr::new(endpoint.address, request.endpoint_port);
        let underlay = network::underlay(endpoint.ip(), None)?;
        self.close_guard()?;
        self.cleanup_routes()?;
        self.add_route(network::endpoint_route(underlay, endpoint.ip()))?;
        let adapter = Adapter::create()?;
        // The closed tunnel allowance admits only the carrier to its enrolled
        // endpoint. Adapter routing and DNS are installed before opening inner I/O.
        self.firewall
            .apply(self.session_plan(&request, &[endpoint], None))?;
        let cancel = Arc::clone(&self.cancel);
        let epoch = self.operation_epoch;
        let (wireguard_endpoint, carrier) = tokio::select! {
            biased;
            _ = cancel.changed(epoch) => return Err(io::ErrorKind::Interrupted.into()),
            result = carrier::start(&request, endpoint, underlay) => result?,
        };
        adapter.configure(
            &request.private_key,
            &request.server_public_key,
            wireguard_endpoint,
            &network_plan::allowed_ips(&request),
        )?;
        network::configure_adapter(adapter.luid(), &request)?;
        for route in network::tunnel_routes(adapter.luid(), &request)? {
            self.add_route(route)?;
        }
        let mtu = sirinvpn_protocol::MtuStatus {
            policy: request.mtu_policy.unwrap_or_default(),
            configured: request.mtu,
            suggested: None,
            outcome: sirinvpn_protocol::MtuProbeOutcome::Pending,
        };
        let active = Active {
            adapter,
            carrier,
            request,
            endpoint,
            underlay,
            started: Instant::now(),
            mtu,
            connected_at: None,
            handshake_marker: None,
            handshake_seen: Instant::now(),
            stats: None,
            epoch: uuid::Uuid::new_v4(),
        };
        self.active = Some(active);
        self.firewall
            .apply(self.plan().ok_or(io::ErrorKind::InvalidInput)?)?;
        self.active
            .as_ref()
            .expect("active adapter")
            .adapter
            .set_up(true)?;
        Ok(())
    }
}
