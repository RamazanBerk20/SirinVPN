use super::*;
use crate::{endpoint_plan, firewall_plan::ControlSocket};
use sirinvpn_protocol::{EndpointDescriptor, EndpointTransitionResponse};
use sirinvpn_transport::{
    EndpointDiscoveryConfig, RelayError, decode_key,
    fetch_endpoint_checkpoint_with_socket_protector,
    offer_endpoint_checkpoint_with_socket_protector,
};
use zeroize::Zeroizing;

#[derive(Default)]
pub(super) struct EndpointMonitor {
    checked: Option<Instant>,
    pending: Option<(EndpointTransitionResponse, Instant)>,
    published: Option<u64>,
    idle_counter: Option<(Instant, u64)>,
}

impl Controller {
    pub(super) async fn apply_endpoint(
        &mut self,
        head: EndpointTransitionResponse,
    ) -> Result<(), ServiceError> {
        let saved = self.saved.as_ref().ok_or(ServiceError::SessionChanged)?;
        let known = saved
            .request
            .endpoint_identity
            .as_ref()
            .ok_or(ServiceError::InvalidRequest)?;
        if sirinvpn_core::current_checkpoint_matches(known, &head) {
            if saved.request.endpoint_checkpoint.as_ref() == Some(&head) {
                return Ok(());
            }
            let mut saved = saved.clone();
            saved.request.endpoint_checkpoint = Some(head);
            self.store.save(&saved).map_err(network_error)?;
            self.saved = Some(saved);
            return Ok(());
        }
        let base = &saved.request;
        let request = endpoint_plan::replacement(base, &head)?;
        let mut resolved = self.resolve(&request).await.map_err(network_error)?;
        let saved = self.saved.as_ref().expect("saved session");
        let known = request
            .endpoint_identity
            .as_ref()
            .expect("validated identity");
        for previous in &saved.endpoints {
            if resolved.len() < 8
                && sirinvpn_tunnel_model::hosts(known).any(|host| host == previous.host)
                && !resolved.contains(previous)
            {
                resolved.push(previous.clone());
            }
        }
        if resolved.is_empty() {
            return Err(ServiceError::NetworkOperation);
        }
        let held = saved.phase == SessionPhase::Held;
        self.hold().await?;
        let mut replacement = self.saved.as_ref().expect("held session").clone();
        replacement.request = request;
        replacement.endpoints = resolved;
        replacement.phase = if held {
            SessionPhase::Held
        } else {
            SessionPhase::Connecting
        };
        self.store.save(&replacement).map_err(network_error)?;
        self.saved = Some(replacement);
        self.close_guard().map_err(network_error)?;
        if held && !saved_policy_kill(&self.saved) {
            self.firewall.clear().map_err(network_error)?;
        }
        self.reset_attempts();
        self.endpoints.pending = None;
        Ok(())
    }

    pub(super) async fn publish_endpoint(
        &mut self,
        head: &EndpointTransitionResponse,
    ) -> Result<(), ServiceError> {
        let saved = self.saved.as_ref().ok_or(ServiceError::SessionChanged)?;
        let request = saved.request.clone();
        let known = request
            .endpoint_identity
            .as_ref()
            .ok_or(ServiceError::InvalidRequest)?;
        if !request.endpoint_publication_enabled
            || (sirinvpn_core::verify_endpoint_checkpoint(known, head).is_err()
                && !sirinvpn_core::current_checkpoint_matches(known, head))
        {
            return Err(ServiceError::InvalidRequest);
        }
        let previous = head
            .claims
            .previous_transports
            .as_ref()
            .ok_or(ServiceError::InvalidRequest)?;
        if previous.endpoint.host == head.claims.endpoint.host {
            self.endpoints.published = Some(head.claims.generation);
            return Ok(());
        }
        // The old source is authenticated by the signed descriptor. This request
        // is only a DNS query plan and is never saved or applied as a tunnel config.
        let mut source = request.clone();
        source.endpoint_host = previous.endpoint.host.clone();
        source.endpoint_identity = None;
        let addresses = self.resolve(&source).await.map_err(network_error)?;
        for address in addresses {
            let Some(config) = control_config(previous, &request.private_key, address.address)?
            else {
                continue;
            };
            if self
                .control_exchange(config, Some(head))
                .await
                .map_err(network_error)?
                .is_some()
            {
                self.endpoints.published = Some(head.claims.generation);
                return Ok(());
            }
        }
        Err(ServiceError::NetworkOperation)
    }

    pub(super) async fn inspect_endpoints(&mut self) -> io::Result<()> {
        let Some(saved) = &self.saved else {
            return Ok(());
        };
        let Some(known) = saved.request.endpoint_identity.clone() else {
            return Ok(());
        };
        if saved.phase == SessionPhase::Held
            || saved.phase == SessionPhase::Disconnecting
            || (!saved.request.connection_policy().automatic_reconnect
                && (self.had_connected || self.attempt_index > 0))
        {
            return Ok(());
        }
        let healthy = self
            .active
            .as_ref()
            .is_some_and(|active| active.connected_at.is_some());
        let count = self
            .active
            .as_ref()
            .and_then(|active| active.stats)
            .and_then(|stats| stats.rx_bytes.checked_add(stats.tx_bytes));
        let now = Instant::now();
        let idle = if healthy {
            if let Some(counter) = count {
                match self.endpoints.idle_counter {
                    Some((at, before)) if at.elapsed() >= Duration::from_secs(10) => {
                        self.endpoints.idle_counter = Some((now, counter));
                        at.elapsed() <= Duration::from_secs(90)
                            && counter >= before
                            && counter - before <= 32 * 1024
                    }
                    None => {
                        self.endpoints.idle_counter = Some((now, counter));
                        false
                    }
                    _ => false,
                }
            } else {
                false
            }
        } else {
            true
        };
        if self
            .endpoints
            .checked
            .is_none_or(|at| at.elapsed() >= Duration::from_secs(60))
        {
            self.endpoints.checked = Some(now);
            let private = Zeroizing::new(saved.request.private_key.clone());
            let publish = saved.request.endpoint_publication_enabled;
            let addresses = self
                .active
                .as_ref()
                .map(|active| active.endpoint.ip())
                .into_iter()
                .chain(saved.endpoints.iter().map(|endpoint| endpoint.address))
                .take(2)
                .collect::<Vec<_>>();
            for address in addresses {
                let Some(config) = control_config(&known.descriptor, &private, address)
                    .map_err(|_| io::ErrorKind::InvalidData)?
                else {
                    break;
                };
                let Some(bytes) = self.control_exchange(config, None).await? else {
                    continue;
                };
                let Ok(head) = serde_json::from_slice::<EndpointTransitionResponse>(&bytes) else {
                    continue;
                };
                if sirinvpn_core::verify_endpoint_checkpoint(&known, &head).is_ok() {
                    if self
                        .endpoints
                        .pending
                        .as_ref()
                        .is_none_or(|(pending, _)| pending != &head)
                    {
                        self.endpoints.pending = Some((head.clone(), now));
                    }
                } else if sirinvpn_core::current_checkpoint_matches(&known, &head) {
                    self.apply_endpoint(head.clone())
                        .await
                        .map_err(|_| io::ErrorKind::Other)?;
                } else {
                    continue;
                }
                if publish && self.endpoints.published != Some(head.claims.generation) {
                    let _ = self.publish_endpoint(&head).await;
                }
                break;
            }
        }
        if self.endpoints.pending.as_ref().is_some_and(|(_, since)| {
            idle || !healthy || since.elapsed() >= Duration::from_secs(180)
        }) {
            let head = self
                .endpoints
                .pending
                .as_ref()
                .expect("pending head")
                .0
                .clone();
            self.apply_endpoint(head)
                .await
                .map_err(|_| io::ErrorKind::Other)?;
        }
        Ok(())
    }

    /// Temporary permissions close on success, rejection, cancellation, and timeout.
    async fn control_exchange(
        &mut self,
        config: EndpointDiscoveryConfig,
        head: Option<&EndpointTransitionResponse>,
    ) -> io::Result<Option<Vec<u8>>> {
        let address = config.server_address;
        let underlay = match network::underlay(address.ip(), None) {
            Ok(underlay) => underlay,
            Err(_) => return Ok(None),
        };
        let base = self.control_plan();
        if let Some(base) = &base {
            self.firewall
                .apply(base.clone().with_control(&[ControlSocket {
                    address,
                    protocol: 6,
                    interface_luid: underlay.luid,
                }]))?;
        } else if !self.firewall.absent()? {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        let cancel = Arc::clone(&self.cancel);
        let epoch = self.operation_epoch;
        let exchange = async {
            let protect = move |socket: &socket2::Socket| {
                network::protect_socket(socket, underlay, address.is_ipv6())
                    .map_err(RelayError::from)
            };
            if let Some(head) = head {
                let encoded =
                    serde_json::to_vec(head).map_err(|_| RelayError::InvalidConfiguration)?;
                offer_endpoint_checkpoint_with_socket_protector(config, &encoded, protect)
                    .await
                    .map(|accepted| accepted.then(Vec::new))
            } else {
                fetch_endpoint_checkpoint_with_socket_protector(config, protect).await
            }
        };
        let response = tokio::select! {
            biased;
            _ = cancel.changed(epoch) => None,
            response = exchange => response.ok().flatten(),
        };
        if let Some(base) = base {
            self.firewall.apply(base)?;
        }
        Ok(response)
    }
}

fn control_config(
    descriptor: &EndpointDescriptor,
    private: &str,
    address: std::net::IpAddr,
) -> Result<Option<EndpointDiscoveryConfig>, ServiceError> {
    let Some(tls) = &descriptor.tls_like else {
        return Ok(None);
    };
    Ok(Some(EndpointDiscoveryConfig {
        server_address: SocketAddr::new(
            address,
            descriptor.endpoint_discovery_port.unwrap_or(tls.port),
        ),
        server_name: tls
            .https
            .as_ref()
            .map_or("www.example.com", |https| &https.server_name)
            .to_owned(),
        client_private_key: Zeroizing::new(
            decode_key(private).map_err(|_| ServiceError::InvalidRequest)?,
        ),
        server_public_key: decode_key(&tls.server_public_key)
            .map_err(|_| ServiceError::InvalidRequest)?,
        socket_mark: None,
    }))
}
