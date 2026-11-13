use super::*;
use crate::{carrier, network_plan};
use sirinvpn_tunnel_model::request_for_reconnect_candidate;

const HANDSHAKE_WINDOW: Duration = Duration::from_secs(12);
const STALE_HANDSHAKE: Duration = Duration::from_secs(240);

impl Controller {
    pub(crate) async fn tick(&mut self) {
        self.operation_epoch = self.cancel.epoch.load(Ordering::SeqCst);
        if let Err(error) = self.tick_inner().await
            && error.kind() != io::ErrorKind::Interrupted
        {
            self.fail().await;
        }
        self.publish();
    }

    async fn tick_inner(&mut self) -> io::Result<()> {
        let Some(saved) = &self.saved else {
            return Ok(());
        };
        // Finishing a committed Disconnect does not depend on the routing driver.
        if saved.phase == SessionPhase::Disconnecting {
            self.disconnect().await.map_err(|_| io::ErrorKind::Other)?;
            return Ok(());
        }
        if saved.phase != SessionPhase::Held
            && saved.request.routing.mode
                == sirinvpn_tunnel_model::TunnelRoutingMode::SelectedApplications
            && !self.application_driver_ready()
        {
            return Err(io::ErrorKind::PermissionDenied.into());
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
        if let Some(active) = self.link.active_mut() {
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
            drop(self.advance(Event::Handshake));
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
            let established = self.link.connected().is_some();
            // An established tunnel first retries its own transport on the new path.
            self.transition(if established {
                Event::PathLost
            } else {
                Event::TrialFailed
            })
            .await;
            self.cleanup_routes()?;
            let automatic = self
                .saved
                .as_ref()
                .expect("saved session")
                .request
                .connection_policy()
                .automatic_reconnect;
            if established && !automatic {
                self.hold().await.map_err(|_| io::ErrorKind::Other)?;
                return Ok(());
            }
            let saved = self.saved.as_mut().expect("saved session");
            saved.phase = SessionPhase::Connecting;
            self.persist()?;
        }
        if self.link.active().is_some() {
            self.inspect_measurements().await?;
            return Ok(());
        }
        let now = Instant::now();
        let Some(attempts) = self.link.due(now) else {
            return Ok(());
        };
        if attempts.exhausted(self.attempt_count(), now) {
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
            let (fresh, cdn_address) = self.resolve(&request).await?;
            if !fresh.is_empty() || cdn_address.is_some() {
                let saved = self.saved.as_mut().expect("saved session");
                if !fresh.is_empty() {
                    saved.endpoints = fresh;
                }
                if cdn_address.is_some() {
                    saved.request.cdn_address = cdn_address;
                }
                self.persist()?;
            }
            drop(self.advance(Event::PassExhausted));
            return Ok(());
        }
        if self.start_attempt(attempts.index).await.is_err() {
            let kind = self
                .saved
                .as_ref()
                .and_then(|saved| {
                    saved
                        .request
                        .reconnect_candidates
                        .get(attempts.index % saved.request.reconnect_candidates.len().max(1))
                })
                .map(|candidate| candidate.transport);
            if let Some(previous) = kind.and_then(|kind| self.quality.failed_trial(kind)) {
                self.change_quality_transport(previous).await?;
                return Ok(());
            }
            self.close_guard()?;
            self.transition(Event::TrialFailed).await;
            self.cleanup_routes()?;
        }
        Ok(())
    }

    fn attempt_count(&self) -> usize {
        self.saved.as_ref().map_or(0, |saved| {
            saved.endpoints.len() * saved.request.reconnect_candidates.len().max(1)
        })
    }

    async fn start_attempt(&mut self, attempt: usize) -> io::Result<()> {
        let saved = self.saved.as_ref().ok_or(io::ErrorKind::InvalidInput)?;
        let count = saved.request.reconnect_candidates.len().max(1);
        let endpoint = saved
            .endpoints
            .get(attempt / count)
            .ok_or(io::ErrorKind::InvalidInput)?;
        let mut request =
            if let Some(candidate) = saved.request.reconnect_candidates.get(attempt % count) {
                request_for_reconnect_candidate(&saved.request, candidate)
            } else {
                saved.request.clone()
            };
        request.endpoint_host = endpoint.host.clone();
        // HTTPS through a CDN goes to the CDN's address; the firewall admits only that.
        let through_cdn = request.https.as_ref().is_some_and(|https| https.cdn);
        let address = request
            .outer_address(endpoint.address)
            .ok_or(io::ErrorKind::AddrNotAvailable)?;
        let endpoint = SocketAddr::new(address, request.endpoint_port);
        let underlay = network::underlay(endpoint.ip(), None)?;
        self.close_guard()?;
        self.cleanup_routes()?;
        // A CDN address is shared anycast: a host route would take every other site on it
        // out of the tunnel. The carrier connects before tunnel routes exist and its
        // socket stays on the underlay through IP_UNICAST_IF (`protect_socket`).
        if !through_cdn {
            self.add_route(network::endpoint_route(underlay, endpoint.ip()))?;
        }
        let listen_port = network_plan::wireguard_listen_port(request.transport);
        if listen_port.is_some() && network_plan::require_free_port(network::probe_port).is_err() {
            return Err(io::ErrorKind::AddrInUse.into());
        }
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
            request.preshared_key.as_deref(),
            wireguard_endpoint,
            &network_plan::allowed_ips(&request),
            listen_port,
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
        if let Some(previous) = self.advance(Event::TrialStarted(Box::new(active))) {
            // Only a running attempt without a trial accepts one (a concurrent hold
            // stopped it): close whichever adapter was handed back.
            drop(previous);
            return Err(io::ErrorKind::InvalidInput.into());
        }
        self.firewall
            .apply(self.plan().ok_or(io::ErrorKind::InvalidInput)?)?;
        self.link
            .active()
            .expect("active adapter")
            .adapter
            .set_up(true)?;
        Ok(())
    }
}
