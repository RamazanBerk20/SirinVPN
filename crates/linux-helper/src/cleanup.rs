//! Cleanup.

use super::*;

impl<R: CommandRunner> LinuxNetworkHelper<R> {
    pub(super) fn cleanup_tunnel_owned(&self) -> Result<(), HelperError> {
        let cleanup_state = self.read_state().ok();
        self.suspend_applications()?;
        self.cleanup_application_routes(cleanup_state.as_ref());
        self.stop_transport();
        let _ = self
            .runner
            .run("resolvectl", &["revert", INTERFACE_NAME], None);
        let _ = self
            .runner
            .run("nft", &["delete", "table", "inet", "sirinvpn_client"], None);
        let _ = self
            .runner
            .run("nft", &["delete", "table", "ip6", "sirinvpn_client6"], None);
        if cleanup_state.as_ref().is_some_and(|state| {
            state.routing.allow_lan && state.routing.mode != TunnelRoutingMode::SelectedApplications
        }) {
            if let Some(dns_address) = cleanup_state.as_ref().and_then(|state| state.dns_address) {
                let dns_route = format!("{dns_address}/32");
                let _ = self.runner.run(
                    "ip",
                    &[
                        "-4",
                        "rule",
                        "delete",
                        "to",
                        &dns_route,
                        "table",
                        ROUTING_TABLE,
                        "priority",
                        DNS_RULE_PRIORITY,
                    ],
                    None,
                );
            }
            for (family, routes) in [
                ("-4", IPV4_LAN_ROUTES.as_slice()),
                ("-6", IPV6_LAN_ROUTES.as_slice()),
            ] {
                for (index, route) in routes.iter().enumerate() {
                    let priority = (LAN_RULE_PRIORITY_START + index as u16).to_string();
                    let _ = self.runner.run(
                        "ip",
                        &[
                            family, "rule", "delete", "to", route, "table", "main", "priority",
                            &priority,
                        ],
                        None,
                    );
                }
            }
        }
        let _ = self.runner.run(
            "ip",
            &[
                "-6",
                "rule",
                "delete",
                "not",
                "fwmark",
                ROUTING_TABLE,
                "table",
                ROUTING_TABLE,
                "priority",
                RULE_TUNNEL_PRIORITY,
            ],
            None,
        );
        let _ = self.runner.run(
            "ip",
            &[
                "-6",
                "rule",
                "delete",
                "table",
                "main",
                "suppress_prefixlength",
                "0",
                "priority",
                RULE_MAIN_PRIORITY,
            ],
            None,
        );
        let _ = self.runner.run(
            "ip",
            &[
                "-6",
                "route",
                "delete",
                "default",
                "dev",
                INTERFACE_NAME,
                "table",
                ROUTING_TABLE,
            ],
            None,
        );
        let _ = self.runner.run(
            "ip",
            &[
                "-4",
                "rule",
                "delete",
                "not",
                "fwmark",
                ROUTING_TABLE,
                "table",
                ROUTING_TABLE,
                "priority",
                RULE_TUNNEL_PRIORITY,
            ],
            None,
        );
        let _ = self.runner.run(
            "ip",
            &[
                "-4",
                "rule",
                "delete",
                "table",
                "main",
                "suppress_prefixlength",
                "0",
                "priority",
                RULE_MAIN_PRIORITY,
            ],
            None,
        );
        let _ = self.runner.run(
            "ip",
            &[
                "-4",
                "route",
                "delete",
                "default",
                "dev",
                INTERFACE_NAME,
                "table",
                ROUTING_TABLE,
            ],
            None,
        );
        let _ = self
            .runner
            .run("ip", &["link", "delete", INTERFACE_NAME], None);
        if self.owned_tunnel_state_exists()? {
            return Err(HelperError::NetworkOperationFailed);
        }
        Ok(())
    }

    pub(super) fn start_transport(
        &self,
        request: &TunnelConnectRequest,
        endpoint: IpAddr,
    ) -> Result<()> {
        let server_public_key = request
            .server_transport_public_key
            .as_deref()
            .ok_or_else(|| anyhow!("transport public key is unavailable"))?;
        let server_address = SocketAddr::new(endpoint, request.endpoint_port);
        let config = match request.transport {
            TransportKind::ObfuscatedUdp => ClientTransportConfig::LegacyObfuscatedUdp(
                client_relay_config(server_address, &request.private_key, server_public_key)?,
            ),
            TransportKind::TcpFallback => ClientTransportConfig::Current(
                CurrentClientTransportConfig::TcpFallback(tcp_client_relay_config(
                    server_address,
                    &request.private_key,
                    server_public_key,
                )?),
            ),
            TransportKind::TlsLike => {
                ClientTransportConfig::Current(CurrentClientTransportConfig::TlsLike(
                    tls_like_client_relay_config(
                        server_address,
                        &request.private_key,
                        server_public_key,
                        request
                            .server_certificate_sha256
                            .as_deref()
                            .ok_or_else(|| {
                                anyhow!("TLS-like certificate fingerprint is unavailable")
                            })?,
                    )?
                    .with_https(request.https.clone())?,
                ))
            }
            TransportKind::DirectUdp => bail!("Direct UDP does not use a transport relay"),
        };
        self.write_transport_config_at(&config, &self.carrier_config_path(request.transport))?;
        if self
            .runner
            .run(
                "systemctl",
                &["start", &carrier_unit(request.transport)],
                None,
            )
            .is_err()
        {
            let _ = self.runner.run(
                "systemctl",
                &["stop", &carrier_unit(request.transport)],
                None,
            );
            let _ = remove_file_if_exists(&self.carrier_config_path(request.transport));
            bail!("transport service failed to authenticate")
        }
        Ok(())
    }

    pub(super) fn stop_transport(&self) {
        for kind in [
            TransportKind::ObfuscatedUdp,
            TransportKind::TcpFallback,
            TransportKind::TlsLike,
        ] {
            self.stop_carrier(kind);
        }
        let _ = self
            .runner
            .run("systemctl", &["stop", TRANSPORT_UNIT], None);
        let _ = remove_file_if_exists(&self.transport_config_path());
    }

    fn write_transport_config_at(&self, config: &ClientTransportConfig, path: &Path) -> Result<()> {
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o755)
            .create(&self.runtime_directory)?;
        let temporary = path.with_extension("new");
        let bytes = Zeroizing::new(serde_json::to_vec(config)?);
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&temporary)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        fs::set_permissions(&temporary, fs::Permissions::from_mode(0o600))?;
        fs::rename(temporary, path)?;
        Ok(())
    }

    pub(super) fn carrier_config_path(&self, kind: TransportKind) -> PathBuf {
        self.runtime_directory
            .join(format!("transport-{}.json", carrier_name(kind)))
    }

    pub(super) fn stop_carrier(&self, kind: TransportKind) {
        if kind != TransportKind::DirectUdp && self.carrier_config_path(kind).exists() {
            let _ = self
                .runner
                .run("systemctl", &["stop", &carrier_unit(kind)], None);
            let _ = remove_file_if_exists(&self.carrier_config_path(kind));
        }
    }

    pub(super) fn cleanup_all_owned(&self) -> Result<(), HelperError> {
        let _ = remove_file_if_exists(&self.persistent_directory.join("measurement-identity.json"));
        let _ = remove_file_if_exists(&self.runtime_directory.join("measurement-last"));
        self.cleanup_tunnel_owned()?;
        self.destroy_applications()?;
        let _ = self
            .runner
            .run("nft", &["delete", "table", "inet", "sirinvpn_guard"], None);
        if self.owned_state_exists()? {
            return Err(HelperError::NetworkOperationFailed);
        }
        Ok(())
    }
}

pub(super) fn carrier_name(kind: TransportKind) -> &'static str {
    match kind {
        TransportKind::DirectUdp => "direct_udp",
        TransportKind::ObfuscatedUdp => "obfuscated_udp",
        TransportKind::TcpFallback => "tcp_fallback",
        TransportKind::TlsLike => "tls_like",
    }
}
pub(super) fn carrier_unit(kind: TransportKind) -> String {
    format!("sirinvpn-transport@{}.service", carrier_name(kind))
}
