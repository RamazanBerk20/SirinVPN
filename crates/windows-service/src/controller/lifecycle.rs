use super::*;
use crate::{firewall_plan::ControlSocket, network_plan, resolver, state::ResolvedEndpoint};

impl Controller {
    pub(super) async fn connect(
        &mut self,
        owner: &str,
        request: TunnelConnectRequest,
        switching: bool,
    ) -> Result<(), ServiceError> {
        network_plan::validate(&request)?;
        if request.routing.mode == sirinvpn_tunnel_model::TunnelRoutingMode::SelectedApplications
            && !self.application_driver_ready()
        {
            return Err(ServiceError::ApplicationDriverUnavailable);
        }
        if let Some(saved) = &self.saved
            && (saved.request.policy != request.policy
                || saved.request.routing != request.routing
                || saved.phase == SessionPhase::Disconnecting
                || !switching
                    && (saved.phase != SessionPhase::Held
                        || saved.request.server_id != request.server_id
                        || saved.request.server_public_key != request.server_public_key))
        {
            return Err(ServiceError::SessionChanged);
        }
        let mut endpoints = self.resolve(&request).await.map_err(network_error)?;
        if endpoints.is_empty()
            && !switching
            && let Some(saved) = &self.saved
        {
            endpoints = saved.endpoints.clone();
        }
        if endpoints.is_empty() {
            return Err(ServiceError::NetworkOperation);
        }
        // The old session remains intact if name resolution or validation fails.
        if self.saved.is_some() {
            self.hold().await?;
        }
        let replacement = SavedConnection {
            schema_version: 2,
            owner_sid: owner.to_owned(),
            boot_nonce: self.boot,
            phase: SessionPhase::Connecting,
            request,
            endpoints,
            routes: Vec::new(),
            // A server switch must not release already selected executables
            // onto the underlay. Only explicit Disconnect clears this guard.
            applications: self
                .saved
                .as_ref()
                .map(|saved| saved.applications.clone())
                .unwrap_or_default(),
        };
        self.store.save(&replacement).map_err(network_error)?;
        self.saved = Some(replacement);
        if let Err(error) = self.close_guard() {
            self.enforcement_failed = true;
            if let Some(saved) = &mut self.saved {
                saved.phase = SessionPhase::Held;
            }
            let _ = self.persist();
            return Err(network_error(error));
        }
        self.reset_attempts();
        Ok(())
    }

    pub(super) async fn resolve(
        &mut self,
        request: &TunnelConnectRequest,
    ) -> io::Result<Vec<ResolvedEndpoint>> {
        let resolvers = network::resolvers(request).unwrap_or_default();
        let previous = self.control_plan();
        if previous.is_none() && !self.firewall.absent()? {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        if let Some(previous) = &previous {
            let sockets = resolvers
                .iter()
                .flat_map(|resolver| {
                    [6, 17].map(|protocol| ControlSocket {
                        address: resolver.address,
                        protocol,
                        interface_luid: resolver.underlay.luid,
                    })
                })
                .collect::<Vec<_>>();
            self.firewall
                .apply(previous.clone().with_control(&sockets))?;
        }
        let cancel = Arc::clone(&self.cancel);
        let epoch = self.operation_epoch;
        let result = tokio::select! {
            biased;
            _ = cancel.changed(epoch) => Err(io::ErrorKind::Interrupted.into()),
            resolved = resolver::resolve(request, &resolvers) => Ok(resolved),
        };
        if let Some(previous) = previous {
            self.firewall.apply(previous)?;
        }
        result
    }

    pub(super) async fn hold(&mut self) -> Result<(), ServiceError> {
        if let Some(saved) = &mut self.saved {
            saved.phase = SessionPhase::Held;
        }
        self.persist().map_err(network_error)?;
        self.close_guard().map_err(network_error)?;
        self.stop_active().await.map_err(network_error)?;
        self.cleanup_routes().map_err(network_error)?;
        if !saved_policy_kill(&self.saved) {
            self.firewall.clear().map_err(network_error)?;
        }
        Ok(())
    }

    pub(super) async fn restart(&mut self) -> Result<(), ServiceError> {
        self.hold().await?;
        if let Some(saved) = &mut self.saved {
            saved.phase = SessionPhase::Connecting;
        }
        self.persist().map_err(network_error)?;
        self.close_guard().map_err(network_error)?;
        self.reset_attempts();
        Ok(())
    }

    pub(super) fn reset_attempts(&mut self) {
        self.next_attempt = Instant::now();
        self.pass_started = Instant::now();
        self.attempt_index = 0;
        self.retry_passes = 0;
        self.had_connected = false;
        self.enforcement_failed = false;
        self.endpoints = endpoints::EndpointMonitor::default();
        self.quality = crate::quality_plan::QualityMonitor::default();
    }

    pub(super) async fn disconnect(&mut self) -> Result<(), ServiceError> {
        if let Some(saved) = &mut self.saved {
            saved.phase = SessionPhase::Disconnecting;
        }
        // Commit the explicit stop before touching the guard. A crash at any later
        // step finishes cleanup and cannot turn this Disconnect into an auto-connect.
        self.persist().map_err(network_error)?;
        self.stop_active().await.map_err(network_error)?;
        self.finish_disconnect().map_err(network_error)
    }

    pub(super) fn finish_disconnect(&mut self) -> io::Result<()> {
        self.cleanup_routes()?;
        self.firewall.clear()?;
        self.store.remove()?;
        self.saved = None;
        self.enforcement_failed = false;
        Ok(())
    }

    pub(super) async fn stop_active(&mut self) -> io::Result<()> {
        if let Some(active) = &self.active {
            active.adapter.set_up(false)?;
        }
        if let Some(mut active) = self.active.take() {
            if let Some(carrier) = active.carrier.take() {
                carrier.stop().await;
            }
            drop(active);
        }
        Ok(())
    }

    pub(super) fn cleanup_routes(&mut self) -> io::Result<()> {
        // Reverse creation order: inner routes first, then endpoint bypasses.
        while let Some(record) = self
            .saved
            .as_ref()
            .and_then(|saved| saved.routes.last())
            .cloned()
        {
            network::remove_owned_route(&record)?;
            self.saved.as_mut().expect("saved route").routes.pop();
            self.persist()?;
        }
        Ok(())
    }

    pub(super) fn add_route(&mut self, record: network_plan::RouteRecord) -> io::Result<()> {
        if network::route_exists(&record)? {
            return Ok(());
        }
        let saved = self.saved.as_mut().ok_or(io::ErrorKind::InvalidInput)?;
        if saved.routes.len() >= 1024 {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        saved.routes.push(record.clone());
        self.persist()?;
        if let Err(error) = network::create_route(&record) {
            // Creation is atomic. Do not claim a pre-existing route after an
            // administrator races this operation, even if our key now matches it.
            self.saved.as_mut().expect("route journal").routes.pop();
            self.persist()?;
            return Err(error);
        }
        Ok(())
    }
}
