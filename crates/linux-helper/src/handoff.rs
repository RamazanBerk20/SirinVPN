//! Change the outer carrier without replacing the WireGuard interface or routes.
use super::*;

fn peer_endpoint(request: &TunnelConnectRequest, endpoint: IpAddr) -> String {
    let port = match request.transport {
        TransportKind::DirectUdp => {
            return SocketAddr::new(endpoint, request.endpoint_port).to_string();
        }
        TransportKind::ObfuscatedUdp => CLIENT_RELAY_PORT,
        TransportKind::TcpFallback => TCP_CLIENT_RELAY_PORT,
        TransportKind::TlsLike => TLS_LIKE_CLIENT_RELAY_PORT,
    };
    format!("127.0.0.1:{port}")
}

impl<R: CommandRunner> LinuxNetworkHelper<R> {
    pub(super) fn carrier_endpoint_matches(
        &self,
        request: &TunnelConnectRequest,
        endpoint: IpAddr,
    ) -> bool {
        let expected = peer_endpoint(request, endpoint);
        self.runner
            .output("wg", &["show", INTERFACE_NAME, "endpoints"])
            .is_ok_and(|peers| {
                String::from_utf8_lossy(&peers).lines().any(|line| {
                    let mut fields = line.split_whitespace();
                    fields.next() == Some(request.server_public_key.as_str())
                        && fields.next() == Some(expected.as_str())
                })
            })
    }

    fn set_carrier_endpoint(&self, request: &TunnelConnectRequest, endpoint: IpAddr) -> Result<()> {
        self.runner.run(
            "wg",
            &[
                "set",
                INTERFACE_NAME,
                "peer",
                &request.server_public_key,
                "endpoint",
                &peer_endpoint(request, endpoint),
            ],
            None,
        )
    }

    pub(super) fn repair_carrier_endpoint(
        &self,
        request: &TunnelConnectRequest,
        endpoint: IpAddr,
    ) -> Result<bool> {
        if self.carrier_endpoint_matches(request, endpoint) {
            return Ok(false);
        }
        self.set_carrier_endpoint(request, endpoint)?;
        self.runner
            .kick_tunnel(request.client_address, request.dns_address);
        Ok(true)
    }

    // Called with the operation lock. Preparation never removes the old carrier;
    // verification is bounded and an unsuccessful optimization rolls back once.
    pub(super) fn change_quality_transport(
        &self,
        desired: &PersistentConnection,
        next: &TunnelConnectRequest,
        state: &mut RuntimeState,
    ) -> Result<ReconcileOutcome, HelperError> {
        let previous = current_persistent_request(desired, Some(state));
        if next.transport == previous.transport {
            return Ok(ReconcileOutcome::Healthy);
        }
        if next.server_id != previous.server_id
            || next.server_public_key != previous.server_public_key
        {
            return Err(HelperError::InvalidState);
        }
        let original = state.clone();
        let previous_mtu = state
            .mtu
            .map_or(mtu::session_mtu(&previous), |m| m.configured);
        // ponytail: keep the lower MTU during live handoff; reconnecting can
        // probe a higher ceiling without disrupting established flows.
        let safe_mtu = previous_mtu.min(next.mtu);
        let protected = next.connection_policy().kill_switch;
        if protected {
            self.apply_policy_guard(next, desired.endpoint)?;
        }
        let result = (|| -> Result<()> {
            if next.transport != TransportKind::DirectUdp {
                self.start_transport(next, desired.endpoint)?;
            }
            if safe_mtu != previous_mtu {
                self.runner.run(
                    "ip",
                    &[
                        "link",
                        "set",
                        "dev",
                        INTERFACE_NAME,
                        "mtu",
                        &safe_mtu.to_string(),
                    ],
                    None,
                )?;
            }
            let deadline = std::time::Instant::now() + Duration::from_secs(2);
            let mut verified_since = None;
            while std::time::Instant::now() < deadline {
                // Authenticated packets queued on the old path can roam
                // WireGuard back. Reassert the choice until it has settled.
                if self.repair_carrier_endpoint(next, desired.endpoint)? {
                    verified_since = None;
                }
                if self
                    .runner
                    .tunnel_probe(next.client_address, next.dns_address)
                    && self.carrier_endpoint_matches(next, desired.endpoint)
                {
                    let since = verified_since.get_or_insert_with(std::time::Instant::now);
                    if since.elapsed() >= Duration::from_millis(300) {
                        state.transport = next.transport;
                        state.reconnecting = false;
                        state.mtu = mtu::initial_mtu(next).map(|mut mtu| {
                            mtu.configured = safe_mtu;
                            mtu
                        });
                        state.mtu_sampled_at_unix = None;
                        let quality = state.quality.get_or_insert_with(Default::default);
                        quality.generation = quality.generation.saturating_add(1);
                        quality.health = Default::default();
                        quality.status.sample = None;
                        quality.status.last_switch_reason =
                            Some(sirinvpn_protocol::TransportSwitchReason::QualityImprovement);
                        self.observe_policy(state, next, desired.endpoint);
                        self.write_state(state)?;
                        return Ok(());
                    }
                } else {
                    verified_since = None;
                }
                thread::sleep(Duration::from_millis(100));
            }
            bail!("prepared carrier did not deliver tunnel traffic")
        })();
        if result.is_err() {
            *state = original;
            // Rollback keeps the same WireGuard session and all application routes.
            self.set_carrier_endpoint(&previous, desired.endpoint)
                .map_err(|_| HelperError::NetworkOperationFailed)?;
            if safe_mtu != previous_mtu {
                self.runner
                    .run(
                        "ip",
                        &[
                            "link",
                            "set",
                            "dev",
                            INTERFACE_NAME,
                            "mtu",
                            &previous_mtu.to_string(),
                        ],
                        None,
                    )
                    .map_err(|_| HelperError::NetworkOperationFailed)?;
            }
            if protected {
                self.apply_policy_guard(&previous, desired.endpoint)?;
            }
            self.stop_carrier(next.transport);
            state
                .quality
                .get_or_insert_with(Default::default)
                .status
                .last_switch_reason = Some(sirinvpn_protocol::TransportSwitchReason::Rollback);
            self.observe_policy(state, &previous, desired.endpoint);
            self.write_state(state)
                .map_err(|_| HelperError::NetworkOperationFailed)?;
            return Err(HelperError::NetworkOperationFailed);
        }
        self.stop_carrier(previous.transport);
        if self.transport_config_path().exists() {
            let _ = self
                .runner
                .run("systemctl", &["stop", TRANSPORT_UNIT], None);
            let _ = remove_file_if_exists(&self.transport_config_path());
        }
        Ok(ReconcileOutcome::Healthy)
    }
}
