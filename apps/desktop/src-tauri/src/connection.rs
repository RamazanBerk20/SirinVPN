//! Connection.

use super::*;
use sirinvpn_tunnel_model::TunnelPhase;

#[tauri::command]
pub(super) fn current_network_profile(state: State<'_, AppState>) -> NetworkProfile {
    state
        .paths
        .network_policy_store()
        .network_profile()
        .unwrap_or_default()
}

pub(super) async fn connect_candidate_automatically(
    profile: ServerProfile,
    secret: SecretIdentity,
) -> Result<(), String> {
    let unavailable = sirinvpn_transport::AutomaticConnectError::Unavailable.to_string();
    for candidate in sirinvpn_core::endpoint_connection_candidates(&profile).await {
        match connect_candidate_at_endpoint(candidate, secret.clone()).await {
            Ok(()) => return Ok(()),
            Err(error) if error == unavailable => continue,
            Err(error) => return Err(error),
        }
    }
    Err(unavailable)
}

async fn connect_candidate_at_endpoint(
    profile: ServerProfile,
    secret: SecretIdentity,
) -> Result<(), String> {
    let bootstrap =
        matches!(profile.client_tunnel_address, IpAddr::V4(address) if address.octets()[3] >= 224);
    let local = invoke_helper("status", None).map_err(safe_error)?;
    if local.phase() != Some(TunnelPhase::Idle) {
        return Err(
            "Disconnect before testing the new server address.".to_owned(),
        );
    }
    let selections = TransportEngine
        .automatic_plan(&profile, NetworkProfile::Automatic, None)
        .map_err(safe_error)?;
    let reconnect_plan = selections.clone();
    let expected_server_id = profile.id;
    let attempt_profile = profile.clone();
    let attempt_secret = secret.clone();
    establish_automatic(
        selections,
        move |selection| {
            let profile = attempt_profile.clone();
            let secret = attempt_secret.clone();
            let reconnect_plan = reconnect_plan.clone();
            async move {
                let management = match ManagementClient::new(&profile, &secret) {
                    Ok(management) => management,
                    Err(error) => return AutomaticAttempt::Abort(safe_error(error)),
                };
                let local = match tauri::async_runtime::spawn_blocking(move || {
                    connect_profile_with_transport_plan(
                        &profile,
                        &secret,
                        false,
                        selection.kind,
                        &reconnect_plan,
                    )
                    .map_err(safe_error)
                })
                .await
                {
                    Ok(Ok(local)) => local,
                    Ok(Err(_)) if selection.kind != TransportKind::DirectUdp => {
                        return AutomaticAttempt::Unavailable;
                    }
                    Ok(Err(error)) => return AutomaticAttempt::Abort(error),
                    Err(_) => {
                        return AutomaticAttempt::Abort(
                            "Testing the new address was interrupted.".to_owned(),
                        );
                    }
                };
                if local.server_id != Some(expected_server_id)
                    || local.state == ConnectionState::Disconnected
                    || local.transport != Some(selection.kind)
                {
                    return AutomaticAttempt::Abort(
                        "This device couldn’t connect to the new address.".to_owned(),
                    );
                }
                match management.status().await {
                    Ok(server) if server.interface_up => AutomaticAttempt::Connected(()),
                    Ok(_) => AutomaticAttempt::Abort(
                        "The server didn’t confirm the VPN connection.".to_owned(),
                    ),
                    Err(ManagementError::RequestRejected {
                        code: sirinvpn_protocol::ErrorCode::AuthorizationFailed,
                        ..
                    }) if bootstrap => AutomaticAttempt::Connected(()),
                    Err(ManagementError::ConnectionFailed) => AutomaticAttempt::Unavailable,
                    Err(error) => AutomaticAttempt::Abort(safe_error(error)),
                }
            }
        },
        move |transport| async move {
            tauri::async_runtime::spawn_blocking(move || {
                cleanup_automatic_attempt(expected_server_id, transport)
            })
            .await
            .map_err(|_| "Closing the test connection was interrupted. Disconnect before trying again.".to_owned())?
        },
    )
    .await
    .map(|_| ())
    .map_err(safe_error)
}

pub(super) fn cleanup_automatic_attempt(
    server_id: ServerId,
    transport: TransportKind,
) -> Result<(), String> {
    let local = invoke_helper("status", None).map_err(safe_error)?;
    if local.phase() == Some(TunnelPhase::Idle) {
        return Ok(());
    }
    if local.server_id != Some(server_id) || local.transport != Some(transport) {
        return Err("The VPN connection changed during the test. Check its status before trying again.".to_owned());
    }
    disconnect_candidate(server_id)
}

pub(super) fn connect_profile_with_transport_plan(
    profile: &ServerProfile,
    secret: &SecretIdentity,
    persistent_protection: bool,
    requested_transport: TransportKind,
    reconnect_plan: &[TransportSelection],
) -> Result<LocalTunnelStatus> {
    connect_profile_with_transport_plan_and_routing(
        profile,
        secret,
        persistent_protection,
        requested_transport,
        reconnect_plan,
        &TunnelRoutingPolicy::default(),
    )
}

pub(super) fn connect_profile_with_transport_plan_and_routing(
    profile: &ServerProfile,
    secret: &SecretIdentity,
    persistent_protection: bool,
    requested_transport: TransportKind,
    reconnect_plan: &[TransportSelection],
    routing: &TunnelRoutingPolicy,
) -> Result<LocalTunnelStatus> {
    let transport = TransportEngine.select(profile, requested_transport)?;
    let candidates = if persistent_protection {
        automatic_reconnect_candidates(reconnect_plan, transport.kind)
    } else {
        Vec::new()
    };
    let request = connection_policy::tunnel_request(
        profile,
        secret,
        transport,
        routing,
        None,
        persistent_protection,
        candidates,
    )?;
    let input = Zeroizing::new(serde_json::to_vec(&request)?);
    invoke_helper("connect", Some(input.as_slice()))
}

#[tauri::command]
pub(super) async fn disconnect_server() -> Result<LocalTunnelStatus, String> {
    let cancellation = crate::connection_controller::cancel()?;
    tauri::async_runtime::spawn_blocking(move || disconnect_cancelled(cancellation))
        .await
        .map_err(|_| "Disconnecting was interrupted. Check the connection status.".to_owned())?
}

/// Disconnect under an acquired cancellation; the tray and window share it.
pub(crate) fn disconnect_cancelled(
    cancellation: crate::connection_controller::CancellationGuard,
) -> Result<LocalTunnelStatus, String> {
    let status = invoke_helper("status", None).map_err(safe_error)?;
    let result = if status.connection_control_supported
        && let Some(id) = status.server_id
    {
        crate::connection_controller::session_action("disconnect-session", id)
    } else {
        invoke_helper("disconnect", None).map_err(safe_error)
    };
    // A pending connect observes the cancellation epoch before committing,
    // or removes its own late candidate. Its completion is part of Stop.
    cancellation.wait_for_connect();
    result?;
    invoke_helper("status", None).map_err(safe_error)
}

#[tauri::command]
pub(super) async fn local_status(state: State<'_, AppState>) -> Result<LocalTunnelStatus, String> {
    static READER: std::sync::LazyLock<std::sync::Arc<tokio::sync::Semaphore>> =
        std::sync::LazyLock::new(|| std::sync::Arc::new(tokio::sync::Semaphore::new(1)));
    let permit = READER
        .clone()
        .acquire_owned()
        .await
        .map_err(|_| "The status reader closed.".to_owned())?;
    let paths = state.paths.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let _permit = permit;
        let local = invoke_helper("status", None).map_err(safe_error)?;
        if let Some(head) = &local.endpoint_checkpoint
            && !has_pending_key_rotation(&paths, head.claims.server_id).unwrap_or(true)
        {
            let _ = paths
                .profile_store()
                .apply_endpoint_checkpoint(head.clone());
        }
        Ok(local)
    })
    .await
    .map_err(|_| "Reading the VPN status was interrupted.".to_owned())?
}

#[tauri::command]
pub(super) async fn server_status(
    state: State<'_, AppState>,
    server_id: String,
) -> Result<ServerStatus, String> {
    let mut profile = find_profile(&state.paths, &server_id)?;
    let secret = state
        .paths
        .secret_store()
        .get(&profile.identity_reference)
        .map_err(safe_error)?;
    let status = ManagementClient::new(&profile, &secret)
        .map_err(safe_error)?
        .status()
        .await
        .map_err(safe_error)?;
    reconcile_status_authority(&state.paths, &mut profile, &status);
    Ok(status)
}

/// Writes only the caller fields of a fresh status, onto the saved profile as it is
/// now and only while it still holds the identity that asked. A stream can outlive a
/// rename, an endpoint checkpoint or a key rotation; none of those is undone.
pub(super) fn reconcile_status_authority(
    paths: &ClientPaths,
    profile: &mut ServerProfile,
    status: &ServerStatus,
) {
    if !profile.clone().adopt_caller_status(status) {
        return;
    }
    let asked_as = profile.client_management_certificate_pem.clone();
    if let Ok(Some(latest)) = paths.profile_store().update(profile.id, |current| {
        Ok((current.client_management_certificate_pem == asked_as
            && current.adopt_caller_status(status))
        .then(|| current.clone()))
    }) {
        *profile = latest;
    }
}

/// Close only the candidate this operation owns. The helper rechecks the identity
/// while holding its network lock so a different session cannot be disconnected.
pub(super) fn disconnect_candidate(server_id: ServerId) -> Result<(), String> {
    let local = invoke_helper("status", None).map_err(safe_error)?;
    if local.phase() == Some(TunnelPhase::Idle) {
        return Ok(());
    }
    if local.server_id != Some(server_id) {
        return Err("The VPN connection changed during setup. Check its status before trying again.".into());
    }
    let input = serde_json::to_vec(&server_id).map_err(safe_error)?;
    invoke_helper("disconnect-session", Some(&input))
        .map(|_| ())
        .map_err(safe_error)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn caller_authority_never_rewrites_a_profile_changed_meanwhile() {
        let directory = tempfile::tempdir().unwrap();
        let paths = ClientPaths::under(directory.path().to_path_buf());
        let saved: ServerProfile = serde_json::from_value(serde_json::json!({
            "schema_version":1,"id":"123e4567-e89b-42d3-a456-426614174001","name":"Before",
            "role":"owner","endpoint":{"host":"example.invalid","wireguard_port":51820},
            "client_tunnel_address":"10.77.0.2","server_tunnel_address":"10.77.0.1",
            "server_wireguard_public_key":"fixture","identity_reference":"fixture",
            "pinned_server_certificate_pem":"fixture","client_management_certificate_pem":"fixture"
        }))
        .unwrap();
        paths.profile_store().insert(saved.clone()).unwrap();
        let status: ServerStatus = serde_json::from_value(serde_json::json!({
            "api_version": sirinvpn_protocol::API_VERSION, "server_name": "VPS",
            "connection_state": "connected", "interface_up": true, "dns_healthy": true,
            "transport": "direct_udp", "peer_count": 1, "rx_bytes": 0, "tx_bytes": 0,
            "uptime_seconds": 1, "caller_role": "member",
        }))
        .unwrap();
        // The stream loaded its copy, then the user renamed the server.
        let mut streamed = saved.clone();
        paths
            .profile_store()
            .update(saved.id, |current| {
                current.name = "Renamed".into();
                Ok(())
            })
            .unwrap();
        reconcile_status_authority(&paths, &mut streamed, &status);
        let stored = &paths.profile_store().load().unwrap()[0];
        assert_eq!(stored.name, "Renamed");
        assert_eq!(stored.role, ServerRole::Member);
        assert_eq!(streamed.name, "Renamed");
        // A rotated identity is not overwritten by a status the old one asked for.
        let mut stale = saved.clone();
        stale.role = ServerRole::Owner;
        paths
            .profile_store()
            .update(saved.id, |current| {
                current.client_management_certificate_pem = "rotated".into();
                current.role = ServerRole::Owner;
                Ok(())
            })
            .unwrap();
        reconcile_status_authority(&paths, &mut stale, &status);
        assert_eq!(paths.profile_store().load().unwrap()[0].role, ServerRole::Owner);
    }
}
