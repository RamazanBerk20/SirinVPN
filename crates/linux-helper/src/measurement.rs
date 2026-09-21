//! Optional optimization: isolated peer measurements followed by an in-place handoff.
use super::*;
use sirinvpn_protocol::TransportQualitySample;

const PROBE_INTERFACE: &str = "sirinprobe0";
const PROBE_TABLE: &str = "51824";
const PROBE_PRIORITY: &str = "9988";
const PROBE_PORT: u16 = 51824;

impl<R: CommandRunner> LinuxNetworkHelper<R> {
    pub fn measure_session(
        &self,
        probe: &MeasureSessionRequest,
    ) -> Result<LocalTunnelStatus, HelperError> {
        let lock = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(self.runtime_directory.join("measurement.lock"))
            .map_err(|_| HelperError::InvalidState)?;
        lock.try_lock_exclusive()
            .map_err(|_| HelperError::ActivePolicy)?;
        let desired = self.read_persistent()?;
        let snapshot = self.read_state()?;
        let current = current_persistent_request(&desired, Some(&snapshot));
        let status = self.status()?;
        if probe.server_id != snapshot.server_id
            || status.counter_epoch.as_deref() != Some(&probe.counter_epoch)
            || status.state != ConnectionState::Connected
            || current.reconnect_candidates.len() < 2
            || !current.connection_policy().kill_switch
            // A session opened by an older helper may have negotiated a larger
            // TCP MSS. Keep it intact until the next explicit connection.
            || snapshot.mtu.map_or(current.mtu, |mtu| mtu.configured) > mtu::session_mtu(&current)
            || probe.lease.client_address
                != Ipv4Addr::new(10, 77, 1, current.client_address.octets()[3])
            || probe.lease.expires_at_unix <= now_unix() + 10
            || probe.lease.expires_at_unix > now_unix() + 125
            || sirinvpn_core::wireguard_public_key_from_private(&probe.private_key)
                .ok()
                .as_deref()
                != Some(&probe.lease.public_key)
        {
            return Err(HelperError::InvalidState);
        }
        let route = self.physical_default_route_fingerprint();
        let unchanged = || -> bool {
            self.status().is_ok_and(|s| {
                s.server_id == Some(probe.server_id)
                    && s.counter_epoch.as_deref() == Some(&probe.counter_epoch)
                    && s.state == ConnectionState::Connected
                    && s.transport == Some(current.transport)
            }) && self.read_state().is_ok_and(|s| {
                s.quality
                    .as_ref()
                    .map(|q| (q.generation, q.network_changed_at_unix))
                    .unwrap_or_default()
                    == snapshot
                        .quality
                        .as_ref()
                        .map(|q| (q.generation, q.network_changed_at_unix))
                        .unwrap_or_default()
            }) && self.physical_default_route_fingerprint() == route
                && self
                    .read_persistent()
                    .is_ok_and(|p| p.request == desired.request)
                && now_unix() + 5 < probe.lease.expires_at_unix
        };
        let mut winner: Option<TransportQualitySample> = None;
        for candidate in &current.reconnect_candidates {
            if candidate.transport == current.transport || !unchanged() {
                continue;
            }
            let next = request_for_reconnect_candidate(&current, candidate);
            // Two independent comparisons must agree. A failed/blocked probe
            // never changes the working transport, including on older servers.
            let mut wins = 0;
            let mut measured = None;
            for _ in 0..2 {
                if !unchanged() {
                    break;
                }
                let baseline = self.sample_quality(&current);
                let sample = self
                    .runner
                    .measure_candidate(&next, desired.endpoint, probe);
                if let (Some(base), Some(sample)) = (baseline, sample)
                    && sample.probes_received >= base.probes_received
                    && sample.improves(base)
                {
                    wins += 1;
                    measured = Some(sample);
                } else {
                    break;
                }
            }
            if wins == 2
                && let Some(sample) = measured
                && winner.is_none_or(|best| sample.improves(best))
            {
                winner = Some(sample);
            }
        }
        if let Some(winner) = winner {
            let _operation = self.lock_operations()?;
            if unchanged() {
                let mut state = self.read_state()?;
                let next = current
                    .reconnect_candidates
                    .iter()
                    .find(|candidate| candidate.transport == winner.transport)
                    .map(|candidate| request_for_reconnect_candidate(&current, candidate))
                    .ok_or(HelperError::InvalidState)?;
                // A failed optimization is a retained connection, not a reason to
                // enter fallback recovery or retry a worse candidate immediately.
                let _ = self.change_quality_transport(&desired, &next, &mut state);
            }
        }
        self.status()
    }
}

pub(super) fn sample_candidate(
    request: &TunnelConnectRequest,
    endpoint: IpAddr,
    probe: &MeasureSessionRequest,
) -> Option<TransportQualitySample> {
    let helper = LinuxNetworkHelper::system();
    // Only this command uses the fixed probe resources; measurement.lock owns
    // their lifetime. Stale resources from a killed worker are safe to remove.
    if !cleanup_probe() {
        return None;
    }
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .ok()?;
    let result = runtime.block_on(async {
        let server = SocketAddr::new(endpoint, request.endpoint_port);
        let (ready, received) = tokio::sync::oneshot::channel();
        let relay = if request.transport == TransportKind::DirectUdp {
            let _ = ready.send(());
            None
        } else {
            let private = Zeroizing::new(probe.private_key.clone());
            let request = request.clone();
            Some(tokio::spawn(async move {
                let key = request
                    .server_transport_public_key
                    .as_deref()
                    .ok_or_else(|| anyhow!("missing transport identity"))?;
                let local = SocketAddr::from(([127, 0, 0, 1], PROBE_PORT));
                match request.transport {
                    TransportKind::ObfuscatedUdp => {
                        let mut config = client_relay_config(server, &private, key)?;
                        config.local_listen = local;
                        run_client_relay(config, || {
                            let _ = ready.send(());
                        })
                        .await?;
                    }
                    TransportKind::TcpFallback => {
                        let mut config = tcp_client_relay_config(server, &private, key)?;
                        config.local_listen = local;
                        run_tcp_client_relay(config, || {
                            let _ = ready.send(());
                        })
                        .await?;
                    }
                    TransportKind::TlsLike => {
                        let mut config = tls_like_client_relay_config(
                            server,
                            &private,
                            key,
                            request
                                .server_certificate_sha256
                                .as_deref()
                                .ok_or_else(|| anyhow!("missing TLS pin"))?,
                        )?
                        .with_https(request.https.clone())?;
                        config.local_listen = local;
                        run_tls_like_client_relay(config, || {
                            let _ = ready.send(());
                        })
                        .await?;
                    }
                    TransportKind::DirectUdp => unreachable!(),
                }
                Ok::<(), anyhow::Error>(())
            }))
        };
        if !matches!(
            tokio::time::timeout(Duration::from_secs(4), received).await,
            Ok(Ok(()))
        ) {
            if let Some(relay) = relay {
                relay.abort();
            }
            return None;
        }
        let wireguard_endpoint = if relay.is_some() {
            SocketAddr::from(([127, 0, 0, 1], PROBE_PORT))
        } else {
            server
        };
        let task_request = request.clone();
        let private = Zeroizing::new(probe.private_key.clone());
        let address = probe.lease.client_address;
        let result =
            tokio::task::spawn_blocking(move || -> Result<Option<TransportQualitySample>> {
                let run = |args: &[&str]| helper.runner.run("ip", args, None);
                run(&["link", "add", PROBE_INTERFACE, "type", "wireguard"])?;
                if let Err(error) = run(&[
                    "link",
                    "set",
                    PROBE_INTERFACE,
                    "alias",
                    "SirinVPN isolated measurement",
                ]) {
                    // This call just created it; cleanup_probe cannot identify it
                    // safely until the ownership alias has been installed.
                    let _ = run(&["link", "delete", PROBE_INTERFACE]);
                    return Err(error);
                }
                let private = Zeroizing::new(format!("{}\n", private.as_str()));
                helper.runner.run(
                    "wg",
                    &[
                        "set",
                        PROBE_INTERFACE,
                        "private-key",
                        "/dev/stdin",
                        "fwmark",
                        ROUTING_TABLE,
                        "peer",
                        &task_request.server_public_key,
                        "endpoint",
                        &wireguard_endpoint.to_string(),
                        "allowed-ips",
                        &format!("{}/32", task_request.dns_address),
                        "persistent-keepalive",
                        "1",
                    ],
                    Some(private.as_bytes()),
                )?;
                run(&[
                    "address",
                    "add",
                    &format!("{address}/32"),
                    "dev",
                    PROBE_INTERFACE,
                ])?;
                run(&["link", "set", PROBE_INTERFACE, "mtu", "1280", "up"])?;
                run(&[
                    "-4",
                    "route",
                    "add",
                    &format!("{}/32", task_request.dns_address),
                    "dev",
                    PROBE_INTERFACE,
                    "table",
                    PROBE_TABLE,
                ])?;
                run(&[
                    "-4",
                    "rule",
                    "add",
                    "from",
                    &format!("{address}/32"),
                    "table",
                    PROBE_TABLE,
                    "priority",
                    PROBE_PRIORITY,
                ])?;
                // Establish separately so handshake cost is not scored as path RTT.
                let _ = helper.runner.output_with_timeout(
                    "ping",
                    &[
                        "-n",
                        "-4",
                        "-c",
                        "1",
                        "-W",
                        "2",
                        "-I",
                        PROBE_INTERFACE,
                        &task_request.dns_address.to_string(),
                    ],
                    Duration::from_secs(3),
                );
                Ok(helper.sample_quality_on(
                    PROBE_INTERFACE,
                    task_request.dns_address,
                    task_request.transport,
                ))
            })
            .await
            .ok()
            .and_then(Result::ok)
            .flatten();
        if let Some(relay) = relay {
            relay.abort();
            let _ = relay.await;
        }
        result
    });
    cleanup_probe();
    result
}

fn cleanup_probe() -> bool {
    let runner = SystemRunner;
    let Ok(bytes) = runner.output("ip", &["-j", "link", "show", "dev", PROBE_INTERFACE]) else {
        // Do not take over another program's routing table or rule priority.
        return runner
            .output("ip", &["-4", "rule", "show", "priority", PROBE_PRIORITY])
            .is_ok_and(|v| v.is_empty())
            && runner
                .output("ip", &["-4", "route", "show", "table", PROBE_TABLE])
                .map_or(true, |v| v.is_empty());
    };
    if !serde_json::from_slice::<serde_json::Value>(&bytes)
        .ok()
        .and_then(|v| v.as_array().and_then(|a| a.first()).cloned())
        .is_some_and(|v| v["ifalias"] == "SirinVPN isolated measurement")
    {
        return false;
    }
    let _ = runner.run(
        "ip",
        &[
            "-4",
            "rule",
            "delete",
            "table",
            PROBE_TABLE,
            "priority",
            PROBE_PRIORITY,
        ],
        None,
    );
    runner
        .run("ip", &["link", "delete", PROBE_INTERFACE], None)
        .is_ok()
}
