//! Connection.

use super::*;

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
    if local.server_id.is_some() || local.state != ConnectionState::Disconnected {
        return Err(
            "Disconnect the active SirinVPN connection before testing the new endpoint.".to_owned(),
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
                            "The endpoint test worker was interrupted.".to_owned(),
                        );
                    }
                };
                if local.server_id != Some(expected_server_id)
                    || local.state == ConnectionState::Disconnected
                    || local.transport != Some(selection.kind)
                {
                    return AutomaticAttempt::Abort(
                        "The privileged helper did not activate the candidate endpoint.".to_owned(),
                    );
                }
                match management.status().await {
                    Ok(server) if server.interface_up => AutomaticAttempt::Connected(()),
                    Ok(_) => AutomaticAttempt::Abort(
                        "The authenticated VPS did not report an active tunnel.".to_owned(),
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
            .map_err(|_| "The endpoint cleanup worker was interrupted.".to_owned())?
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
    if local.server_id.is_none() && local.state == ConnectionState::Disconnected {
        return Ok(());
    }
    if local.server_id != Some(server_id) || local.transport != Some(transport) {
        return Err("Local tunnel state changed during automatic selection.".to_owned());
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
    tauri::async_runtime::spawn_blocking(|| {
        let _cancellation = cancellation;
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
        while crate::connection_controller::is_busy() {
            std::thread::sleep(std::time::Duration::from_millis(25));
        }
        result?;
        invoke_helper("status", None).map_err(safe_error)
    })
    .await
    .map_err(|_| "The network worker was interrupted.".to_owned())?
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
    .map_err(|_| "The local status worker was interrupted.".to_owned())?
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

pub(super) fn reconcile_status_authority(
    paths: &ClientPaths,
    profile: &mut ServerProfile,
    status: &ServerStatus,
) {
    if let Some(role) = status.caller_role
        && (profile.role != role
            || profile.administrator != status.caller_administrator
            || (status.caller_device_id.is_some() && profile.device_id != status.caller_device_id))
    {
        // A stream can outlive a local rename or preference change.
        let Ok(latest) = find_profile(paths, &profile.id.to_string()) else {
            return;
        };
        *profile = latest;
        profile.role = role;
        profile.administrator = status.caller_administrator;
        if status.caller_device_id.is_some() {
            profile.device_id = status.caller_device_id;
        }
        let _ = paths.profile_store().upsert(profile.clone());
    }
}

/// Close only the candidate this operation owns. The helper rechecks the identity
/// while holding its network lock so a different session cannot be disconnected.
pub(super) fn disconnect_candidate(server_id: ServerId) -> Result<(), String> {
    let local = invoke_helper("status", None).map_err(safe_error)?;
    if local.server_id.is_none() && local.state == ConnectionState::Disconnected {
        return Ok(());
    }
    if local.server_id != Some(server_id) {
        return Err("The active connection changed during enrollment.".into());
    }
    let input = serde_json::to_vec(&server_id).map_err(safe_error)?;
    invoke_helper("disconnect-session", Some(&input))
        .map(|_| ())
        .map_err(safe_error)
}
