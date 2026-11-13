//! Connection.

use super::*;

pub(super) async fn create_endpoint_update(
    paths: &ClientPaths,
    selector: ServerSelector,
    json: bool,
) -> Result<()> {
    let profile = resolve_profile(&paths.profile_store(), &selector.server)?;
    let local = invoke_helper("status", None)?;
    if local.server_id != Some(profile.id) || local.state == ConnectionState::Disconnected {
        bail!("connect to the restored VPS before creating its signed endpoint update");
    }
    let code = create_endpoint_transition(paths, profile.id).await?;
    let result = EndpointUpdateCodeResult {
        server_id: profile.id,
        generation: code.generation(),
        previous_endpoint: code.previous_endpoint().clone(),
        endpoint: code.endpoint().clone(),
        code: code.expose().to_owned(),
    };
    if json {
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        println!(
            "Signed endpoint update {} -> {} (generation {}). Share this public, signed code with each existing device:",
            result.previous_endpoint.socket_label(),
            result.endpoint.socket_label(),
            result.generation,
        );
        println!("{}", result.code);
        println!(
            "Keep the old VPS running. Use `server publish-endpoint-update` to let devices retrieve this update through its private management connection."
        );
    }
    Ok(())
}

pub(super) async fn publish_endpoint_update(
    paths: &ClientPaths,
    arguments: EndpointUpdateCodeArguments,
    json: bool,
) -> Result<()> {
    let profile = resolve_profile(&paths.profile_store(), &arguments.server)?;
    let local = invoke_helper("status", None)?;
    let code = read_endpoint_update_code(arguments.code_stdin)?;
    if local.server_id == Some(profile.id) && local.endpoint_updates_supported {
        let head = sirinvpn_core::DecodedEndpointTransition::decode(code.as_str())?
            .response()
            .clone();
        let encoded = serde_json::to_vec(&head)?;
        invoke_helper("publish-endpoint-checkpoint", Some(&encoded))?;
        return print_value(
            &endpoint_result(&head),
            json,
            "Published the signed handoff while retaining the active connection policy.",
        );
    }
    if local.state != ConnectionState::Disconnected || local.server_id.is_some() {
        bail!("disconnect the other server before publishing this endpoint update");
    }
    let result = publish_endpoint_transition(
        paths,
        profile.id,
        code.as_str(),
        |candidate, secret| async move {
            test_endpoint_automatically(
                &candidate,
                &secret,
                NetworkProfile::Automatic,
                None,
                TunnelRoutingPolicy::default(),
            )
            .await
            .map(|_| ())
            .map_err(|error| error.to_string())
        },
        || disconnect_candidate(profile.id).map_err(|error| error.to_string()),
    )
    .await?;
    print_value(
        &result,
        json,
        "Published the signed endpoint update on the old VPS. Its authorized devices can now retrieve it; the old VPS was not uninstalled.",
    )
}

pub(super) async fn apply_endpoint_update(
    paths: &ClientPaths,
    arguments: EndpointUpdateCodeArguments,
    json: bool,
) -> Result<()> {
    let profile = resolve_profile(&paths.profile_store(), &arguments.server)?;
    let local = invoke_helper("status", None)?;
    let code = if arguments.code_stdin {
        read_endpoint_update_code(true)?.to_string()
    } else {
        if local.server_id != Some(profile.id) || local.state == ConnectionState::Disconnected {
            bail!(
                "connect to the old VPS to retrieve its published update, or pass --code-stdin while disconnected"
            );
        }
        let secret = explicit_secret(paths, &profile.identity_reference)?;
        let response = ManagementClient::new(&profile, &secret)?
            .endpoint_transition()
            .await?
            .ok_or_else(|| anyhow!("the old VPS has no published endpoint update"))?;
        let code = EndpointTransitionCode::from_response(response)?;
        code.expose().to_owned()
    };

    if has_pending_key_rotation(paths, profile.id)? {
        bail!("finish the pending device key rotation before applying this endpoint update");
    }
    if local.server_id == Some(profile.id) && local.endpoint_updates_supported {
        // The same per-server guard as key rotation and the disconnected path below.
        let _operation = sirinvpn_core::ServerOperationLock::acquire(paths, profile.id)?;
        let head = sirinvpn_core::DecodedEndpointTransition::decode(&code)?
            .response()
            .clone();
        let encoded = serde_json::to_vec(&head)?;
        invoke_helper("apply-endpoint-checkpoint", Some(&encoded))?;
        if profile.endpoint_generation < head.claims.generation {
            paths
                .profile_store()
                .apply_endpoint_checkpoint(head.clone())?;
        }
        return print_value(
            &endpoint_result(&head),
            json,
            "Applied the signed endpoint update while retaining protection, routing and MTU settings. Check status for the new connection.",
        );
    }
    if local.state != ConnectionState::Disconnected || local.server_id.is_some() {
        bail!("disconnect the other server before applying this endpoint update");
    }
    let result = apply_endpoint_transition(
        paths,
        profile.id,
        &code,
        |candidate, secret| async move {
            test_endpoint_automatically(
                &candidate,
                &secret,
                NetworkProfile::Automatic,
                None,
                TunnelRoutingPolicy::default(),
            )
            .await
            .map(|_| ())
            .map_err(|error| error.to_string())
        },
        || disconnect_candidate(profile.id).map_err(|error| error.to_string()),
    )
    .await?;
    print_value(
        &result,
        json,
        "The new endpoint passed WireGuard and pinned management verification. The local profile was switched atomically and remains connected without persistent protection.",
    )
}

pub(super) async fn test_endpoint_automatically(
    profile: &ServerProfile,
    secret: &SecretIdentity,
    network_profile: NetworkProfile,
    cached_transport: Option<TransportKind>,
    routing: TunnelRoutingPolicy,
) -> Result<(LocalTunnelStatus, TransportKind)> {
    for candidate in sirinvpn_core::endpoint_connection_candidates(profile).await {
        match test_endpoint_at_address(
            &candidate,
            secret,
            network_profile,
            cached_transport,
            routing.clone(),
        )
        .await
        {
            Ok(result) => return Ok(result),
            Err(error)
                if matches!(
                    error.downcast_ref::<sirinvpn_transport::AutomaticConnectError>(),
                    Some(sirinvpn_transport::AutomaticConnectError::Unavailable)
                ) =>
            {
                continue;
            }
            Err(error) => return Err(error),
        }
    }
    Err(sirinvpn_transport::AutomaticConnectError::Unavailable.into())
}

async fn test_endpoint_at_address(
    profile: &ServerProfile,
    secret: &SecretIdentity,
    network_profile: NetworkProfile,
    cached_transport: Option<TransportKind>,
    routing: TunnelRoutingPolicy,
) -> Result<(LocalTunnelStatus, TransportKind)> {
    let local = invoke_helper("status", None)?;
    if local.server_id.is_some() || local.state != ConnectionState::Disconnected {
        bail!("disconnect the active SirinVPN connection before using automatic selection");
    }
    let bootstrap =
        matches!(profile.client_tunnel_address, IpAddr::V4(address) if address.octets()[3] >= 224);
    let selections = TransportEngine.automatic_plan(profile, network_profile, cached_transport)?;
    let reconnect_plan = selections.clone();
    let established = establish_automatic(
        selections,
        |selection| {
            let reconnect_plan = reconnect_plan.clone();
            let routing = routing.clone();
            async move {
                let management = match ManagementClient::new(profile, secret) {
                    Ok(management) => management,
                    Err(error) => return AutomaticAttempt::Abort(error.to_string()),
                };
                let local = match connect_profile_with_transport_plan_and_routing(
                    profile,
                    secret,
                    false,
                    selection.kind,
                    &reconnect_plan,
                    &routing,
                ) {
                    Ok(local) => local,
                    Err(_) if selection.kind != TransportKind::DirectUdp => {
                        return AutomaticAttempt::Unavailable;
                    }
                    Err(error) => return AutomaticAttempt::Abort(error.to_string()),
                };
                if local.server_id != Some(profile.id)
                    || local.state == ConnectionState::Disconnected
                    || local.transport != Some(selection.kind)
                {
                    return AutomaticAttempt::Abort(
                        "the privileged helper did not activate the attempted transport".to_owned(),
                    );
                }
                match management.status().await {
                    Ok(server) if server.interface_up => AutomaticAttempt::Connected(local),
                    Ok(_) => AutomaticAttempt::Abort(
                        "the authenticated VPS did not report an active tunnel".to_owned(),
                    ),
                    Err(ManagementError::RequestRejected {
                        code: sirinvpn_protocol::ErrorCode::AuthorizationFailed,
                        ..
                    }) if bootstrap => AutomaticAttempt::Connected(local),
                    Err(ManagementError::ConnectionFailed) => AutomaticAttempt::Unavailable,
                    Err(error) => AutomaticAttempt::Abort(error.to_string()),
                }
            }
        },
        |transport| async move { cleanup_automatic_attempt(profile.id, transport) },
    )
    .await?;
    Ok((established.value, established.selection.kind))
}

pub(super) fn cleanup_automatic_attempt(
    server_id: ServerId,
    transport: TransportKind,
) -> Result<()> {
    let local = invoke_helper("status", None)?;
    if local.server_id.is_none() && local.state == ConnectionState::Disconnected {
        return Ok(());
    }
    if local.server_id != Some(server_id) || local.transport != Some(transport) {
        bail!("local tunnel state changed during automatic transport selection");
    }
    disconnect_candidate(server_id)
}

pub(super) fn connect_profile_with_transport_plan(
    profile: &ServerProfile,
    secret: &SecretIdentity,
    persistent: bool,
    requested_transport: TransportKind,
    reconnect_plan: &[TransportSelection],
) -> Result<LocalTunnelStatus> {
    connect_profile_with_transport_plan_and_routing(
        profile,
        secret,
        persistent,
        requested_transport,
        reconnect_plan,
        &TunnelRoutingPolicy::default(),
    )
}

pub(super) fn connect_profile_with_transport_plan_and_routing(
    profile: &ServerProfile,
    secret: &SecretIdentity,
    persistent: bool,
    requested_transport: TransportKind,
    reconnect_plan: &[TransportSelection],
    routing: &TunnelRoutingPolicy,
) -> Result<LocalTunnelStatus> {
    let request = build_tunnel_request(
        profile,
        secret,
        persistent,
        requested_transport,
        reconnect_plan,
        routing,
    )?;
    let payload = Zeroizing::new(serde_json::to_vec(&request)?);
    invoke_helper("connect", Some(payload.as_slice()))
}

pub(super) fn build_tunnel_request(
    profile: &ServerProfile,
    secret: &SecretIdentity,
    persistent: bool,
    requested_transport: TransportKind,
    reconnect_plan: &[TransportSelection],
    routing: &TunnelRoutingPolicy,
) -> Result<TunnelConnectRequest> {
    let transport = TransportEngine.select(profile, requested_transport)?;
    let client_address = match profile.client_tunnel_address {
        IpAddr::V4(address) => address,
        IpAddr::V6(_) => bail!("SirinVPN does not support an IPv6 client tunnel address yet"),
    };
    let dns_address = match profile.server_tunnel_address {
        IpAddr::V4(address) => address,
        IpAddr::V6(_) => bail!("SirinVPN does not support an IPv6 DNS address yet"),
    };
    let request = TunnelConnectRequest {
        endpoint_identity: Some(profile.endpoint_identity()),
        endpoint_checkpoint: None,
        endpoint_publication_enabled: profile.role == ServerRole::Owner,
        endpoint_dns_servers: Vec::new(),
        cdn_address: None,
        mtu_policy: Some(sirinvpn_protocol::MtuPolicy::Automatic),
        policy: Some(ConnectionPolicy::legacy(persistent)),
        // Set from `required_schema` below, once every feature field is in place.
        schema_version: 0,
        server_id: profile.id,
        endpoint_host: transport.network_endpoint.host,
        endpoint_port: transport.network_endpoint.wireguard_port,
        transport: transport.kind,
        server_transport_public_key: transport.server_transport_public_key,
        https: transport.https,
        server_certificate_sha256: transport.server_certificate_sha256,
        reconnect_candidates: if persistent {
            automatic_reconnect_candidates(reconnect_plan, transport.kind)
        } else {
            Vec::new()
        },
        client_address,
        server_public_key: profile.server_wireguard_public_key.clone(),
        private_key: secret.wireguard_private_key.clone(),
        preshared_key: secret.wireguard_preshared_key.clone(),
        dns_address,
        client_ipv6_address: if profile.ipv6_tunnel_enabled {
            Some(
                ipv6_tunnel_address(profile.id, client_address)
                    .ok_or_else(|| anyhow!("the profile cannot derive its IPv6 tunnel address"))?,
            )
        } else {
            None
        },
        mtu: transport.mtu,
        persistent_protection: false,
        routing: routing.clone(),
        subnet_routes: sirinvpn_tunnel_model::request_subnet_routes(
            &profile.subnet_routes,
            routing,
        ),
    };
    let mut request = request;
    request.schema_version = request.required_schema();
    Ok(request)
}

pub(super) fn disconnect(json: bool) -> Result<()> {
    let status = invoke_helper("disconnect", None)?;
    print_value(&status, json, "Disconnected and restored local networking.")
}

pub(super) async fn status(paths: &ClientPaths, json: bool) -> Result<()> {
    let local = invoke_helper("status", None)?;
    if let Some(head) = &local.endpoint_checkpoint
        && !has_pending_key_rotation(paths, head.claims.server_id).unwrap_or(true)
    {
        let _ = paths
            .profile_store()
            .apply_endpoint_checkpoint(head.clone());
    }
    // A missing profile or locked keyring must not hide the local tunnel and traffic block.
    let identity = local.server_id.and_then(|server_id| {
        let profile = resolve_profile(&paths.profile_store(), &server_id.to_string()).ok()?;
        let secret = paths.secret_store().get(&profile.identity_reference).ok()?;
        Some((profile, secret))
    });
    let server = if let Some((profile, secret)) = &identity {
        match ManagementClient::new(profile, secret) {
            Ok(client) => match client.status().await {
                Ok(status) => {
                    adopt_caller_status(paths, profile, &status);
                    Some(status)
                }
                Err(_) => None,
            },
            Err(_) => None,
        }
    } else {
        None
    };
    // Only a VPS that just answered is asked, so an unreachable one is not waited on twice.
    let key_hint = match (&server, &identity) {
        (Some(_), Some((profile, secret))) => preshared_key_hint(profile, secret).await,
        _ => None,
    };
    let combined = CombinedStatus {
        local,
        server,
        preshared_key_rotation_recommended: key_hint.is_some(),
    };
    if json {
        println!("{}", serde_json::to_string_pretty(&combined)?);
    } else {
        println!("Local tunnel: {:?}", combined.local.state);
        if let Some(quality) = &combined.local.transport_quality {
            println!("Transport comparison: {:?}", quality.selection);
            if let Some(sample) = quality.sample {
                println!(
                    "Private path: {:.1} ms latency; {:.1} ms jitter; {}/{} probes delivered",
                    f64::from(sample.latency_micros) / 1000.0,
                    f64::from(sample.jitter_micros) / 1000.0,
                    sample.probes_received,
                    sample.probes_sent
                );
            }
        }
        if let Some(mtu) = combined.local.mtu {
            println!(
                "MTU: {} ({:?}); measured suggestion: {:?}; probe: {:?}",
                mtu.configured, mtu.policy, mtu.suggested, mtu.outcome
            );
        }
        println!(
            "Kill switch: {:?}; automatic reconnect configured: {}; connect on startup: {}",
            combined
                .local
                .kill_switch_state
                .unwrap_or(sirinvpn_tunnel_model::KillSwitchState::Unknown),
            combined.local.auto_reconnect_enabled,
            combined.local.connect_on_startup
        );
        if let Some(server) = combined.server {
            println!(
                "Server: {} | DNS: {} ({}, {} private record(s)) | peers: {} | RX: {} | TX: {}",
                server.server_name,
                if server.dns_healthy {
                    "healthy"
                } else {
                    "unavailable"
                },
                dns_upstream_label(&server.dns_upstream),
                server.private_dns_records.len(),
                server.peer_count,
                server.rx_bytes,
                server.tx_bytes
            );
        }
        if let Some(hint) = key_hint {
            println!("{hint}");
        }
    }
    Ok(())
}

/// Applies the caller fields of a fresh status to the saved profile as it is now, and
/// only while it still holds the identity that asked. Returns the saved profile when
/// those fields changed.
pub(super) fn adopt_caller_status(
    paths: &ClientPaths,
    asked_as: &ServerProfile,
    status: &sirinvpn_protocol::ServerStatus,
) -> Option<ServerProfile> {
    paths
        .profile_store()
        .update(asked_as.id, |current| {
            Ok((current.client_management_certificate_pem
                == asked_as.client_management_certificate_pem
                && current.adopt_caller_status(status))
            .then(|| current.clone()))
        })
        .ok()
        .flatten()
}

/// Prints the local tunnel each time its lifecycle phase changes, so scripts, tests
/// and agents can wait on `phase.kind` instead of polling in their own loops.
pub(super) async fn watch_status(json: bool) -> Result<()> {
    let mut last = None;
    loop {
        let local = invoke_helper("status", None)?;
        if let Some(line) = phase_change(&mut last, &local, json)? {
            println!("{line}");
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
}

/// One line for the first snapshot and for every phase change, nothing otherwise.
/// A snapshot with contradictory lifecycle flags has no phase and is reported as such.
pub(super) fn phase_change(
    last: &mut Option<Option<TunnelPhase>>,
    local: &LocalTunnelStatus,
    json: bool,
) -> Result<Option<String>> {
    let phase = local.phase();
    if *last == Some(phase) {
        return Ok(None);
    }
    *last = Some(phase);
    Ok(Some(if json {
        serde_json::to_string(local)?
    } else {
        match phase {
            Some(phase) => format!("Local tunnel: {phase:?}"),
            None => {
                "Local tunnel: unknown (the local service sent a contradictory status)".to_owned()
            }
        }
    }))
}

pub(super) fn disconnect_candidate(server_id: ServerId) -> Result<()> {
    let local = invoke_helper("status", None)?;
    if local.server_id.is_none() && local.state == ConnectionState::Disconnected {
        return Ok(());
    }
    if local.server_id != Some(server_id) {
        bail!("the active connection changed during enrollment");
    }
    let input = serde_json::to_vec(&server_id)?;
    invoke_helper("disconnect-session", Some(&input))?;
    Ok(())
}

fn endpoint_result(
    head: &sirinvpn_protocol::EndpointTransitionResponse,
) -> sirinvpn_core::EndpointTransitionResult {
    sirinvpn_core::EndpointTransitionResult {
        server_id: head.claims.server_id,
        previous_endpoint: head.claims.previous_endpoint.clone(),
        endpoint: head.claims.endpoint.clone(),
        generation: head.claims.generation,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn local(phase: TunnelPhase) -> LocalTunnelStatus {
        let mut status: LocalTunnelStatus = serde_json::from_value(serde_json::json!({
            "state": "disconnected",
            "interface_name": "sirinvpn0",
            "server_id": null,
            "rx_bytes": 0,
            "tx_bytes": 0,
            "ipv6_blocked": false
        }))
        .unwrap();
        status.set_phase(phase);
        status
    }

    #[test]
    fn watch_prints_one_json_line_per_phase_change() {
        let server_id = ServerId::new();
        let mut last = None;
        let mut lines = Vec::new();
        for phase in [
            TunnelPhase::Idle,
            TunnelPhase::Idle,
            TunnelPhase::Connecting { server_id },
            TunnelPhase::Connecting { server_id },
            TunnelPhase::Connected { server_id },
            TunnelPhase::Paused { server_id },
        ] {
            lines.extend(phase_change(&mut last, &local(phase), true).unwrap());
        }
        let kinds: Vec<String> = lines
            .iter()
            .map(|line| {
                assert!(!line.contains('\n'));
                let value: serde_json::Value = serde_json::from_str(line).unwrap();
                value["phase"]["kind"].as_str().unwrap().to_owned()
            })
            .collect();
        assert_eq!(kinds, ["idle", "connecting", "connected", "paused"]);
        // A contradictory snapshot is reported once, without a guessed phase.
        let mut contradictory = local(TunnelPhase::Idle);
        contradictory.waiting_for_user = true;
        let line = phase_change(&mut last, &contradictory, true)
            .unwrap()
            .unwrap();
        assert!(serde_json::from_str::<serde_json::Value>(&line).unwrap()["phase"].is_null());
        assert!(
            phase_change(&mut last, &contradictory, true)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn caller_status_keeps_changes_saved_while_the_cli_was_connecting() {
        let directory = tempfile::tempdir().unwrap();
        let paths = ClientPaths::under(directory.path().into());
        let loaded: ServerProfile = serde_json::from_value(serde_json::json!({
            "schema_version": 1,
            "id": ServerId::new(),
            "name": "Home",
            "endpoint": {"host": "203.0.113.4", "wireguard_port": 51820},
            "client_tunnel_address": "10.77.0.2",
            "server_tunnel_address": "10.77.0.1",
            "server_wireguard_public_key": "public",
            "pinned_server_certificate_pem": "certificate",
            "client_management_certificate_pem": "client-certificate",
            "identity_reference": "identity",
            "role": "member"
        }))
        .unwrap();
        paths.profile_store().insert(loaded.clone()).unwrap();
        // While connecting, a checkpoint moved the endpoint and the user renamed it.
        paths
            .profile_store()
            .update(loaded.id, |current| {
                current.endpoint.host = "198.51.100.9".into();
                current.endpoint_generation = 3;
                current.name = "Renamed".into();
                Ok(())
            })
            .unwrap();
        let status: sirinvpn_protocol::ServerStatus = serde_json::from_value(serde_json::json!({
            "api_version": "1", "server_name": "Home", "connection_state": "connected",
            "interface_up": true, "dns_healthy": true, "transport": "direct_udp",
            "peer_count": 1, "rx_bytes": 0, "tx_bytes": 0, "uptime_seconds": 1,
            "caller_role": "member", "caller_administrator": true
        }))
        .unwrap();
        let saved = adopt_caller_status(&paths, &loaded, &status).unwrap();
        assert!(saved.administrator);
        assert_eq!(
            (saved.endpoint.host.as_str(), saved.endpoint_generation),
            ("198.51.100.9", 3)
        );
        assert_eq!(saved.name, "Renamed");
        assert_eq!(paths.profile_store().load().unwrap(), vec![saved]);

        // A profile whose identity was rotated meanwhile is not touched.
        let mut stale = loaded.clone();
        stale.client_management_certificate_pem = "older-certificate".into();
        let mut demoted = status.clone();
        demoted.caller_administrator = false;
        assert!(adopt_caller_status(&paths, &stale, &demoted).is_none());
        assert!(paths.profile_store().load().unwrap()[0].administrator);
    }
}
