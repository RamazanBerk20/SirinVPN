//! Endpoints.

use super::*;

#[tauri::command]
pub(super) async fn create_endpoint_update(
    state: State<'_, AppState>,
    server_id: String,
) -> Result<EndpointUpdateCodeResult, String> {
    let profile = find_profile(&state.paths, &server_id)?;
    let local = invoke_helper("status", None).map_err(safe_error)?;
    if local.server_id != Some(profile.id) || local.state == ConnectionState::Disconnected {
        return Err(
            "Connect to the restored VPS before creating its signed endpoint update.".to_owned(),
        );
    }
    let code = create_endpoint_transition(&state.paths, profile.id)
        .await
        .map_err(safe_error)?;
    Ok(endpoint_update_code_result(profile.id, code))
}

#[tauri::command]
pub(super) async fn available_endpoint_update(
    state: State<'_, AppState>,
    server_id: String,
) -> Result<Option<EndpointUpdateCodeResult>, String> {
    let profile = find_profile(&state.paths, &server_id)?;
    let local = invoke_helper("status", None).map_err(safe_error)?;
    if local.server_id != Some(profile.id) || local.state == ConnectionState::Disconnected {
        return Err(
            "Connect to this VPS before checking for a published endpoint update.".to_owned(),
        );
    }
    let secret = state
        .paths
        .secret_store()
        .get(&profile.identity_reference)
        .map_err(safe_error)?;
    let response = ManagementClient::new(&profile, &secret)
        .map_err(safe_error)?
        .endpoint_transition()
        .await
        .map_err(safe_error)?;
    response
        .map(EndpointTransitionCode::from_response)
        .transpose()
        .map(|code| code.map(|code| endpoint_update_code_result(profile.id, code)))
        .map_err(safe_error)
}

#[tauri::command]
pub(super) async fn apply_endpoint_update(
    state: State<'_, AppState>,
    input: EndpointUpdateInput,
) -> Result<sirinvpn_core::EndpointTransitionResult, String> {
    let _operation = crate::connection_controller::acquire()?;
    let profile = find_profile(&state.paths, &input.server_id)?;
    crate::connection_controller::require_finished_rotation(&state.paths, profile.id)?;
    let local = invoke_helper("status", None).map_err(safe_error)?;
    if local.server_id == Some(profile.id) && local.endpoint_updates_supported {
        let head = sirinvpn_core::DecodedEndpointTransition::decode(&input.code)
            .map_err(safe_error)?
            .response()
            .clone();
        let encoded = serde_json::to_vec(&head).map_err(safe_error)?;
        invoke_helper("apply-endpoint-checkpoint", Some(&encoded)).map_err(safe_error)?;
        if profile.endpoint_generation < head.claims.generation {
            state
                .paths
                .profile_store()
                .apply_endpoint_checkpoint(head.clone())
                .map_err(safe_error)?;
        }
        return Ok(endpoint_result(&head));
    }
    if local.state != ConnectionState::Disconnected || local.server_id.is_some() {
        return Err("Disconnect the other server before applying this endpoint update.".into());
    }
    apply_endpoint_transition(
        &state.paths,
        profile.id,
        &input.code,
        |candidate, secret| async move { connect_candidate_automatically(candidate, secret).await },
        || disconnect_candidate(profile.id),
    )
    .await
    .map_err(safe_error)
}

#[tauri::command]
pub(super) async fn publish_endpoint_update(
    state: State<'_, AppState>,
    input: EndpointUpdateInput,
) -> Result<sirinvpn_core::EndpointTransitionResult, String> {
    let _operation = crate::connection_controller::acquire()?;
    let profile = find_profile(&state.paths, &input.server_id)?;
    crate::connection_controller::require_finished_rotation(&state.paths, profile.id)?;
    let local = invoke_helper("status", None).map_err(safe_error)?;
    if local.server_id == Some(profile.id) && local.endpoint_updates_supported {
        let head = sirinvpn_core::DecodedEndpointTransition::decode(&input.code)
            .map_err(safe_error)?
            .response()
            .clone();
        let encoded = serde_json::to_vec(&head).map_err(safe_error)?;
        invoke_helper("publish-endpoint-checkpoint", Some(&encoded)).map_err(safe_error)?;
        return Ok(endpoint_result(&head));
    }
    if local.state != ConnectionState::Disconnected || local.server_id.is_some() {
        return Err("Disconnect the other server before publishing this endpoint update.".into());
    }
    publish_endpoint_transition(
        &state.paths,
        profile.id,
        &input.code,
        |candidate, secret| async move { connect_candidate_automatically(candidate, secret).await },
        || disconnect_candidate(profile.id),
    )
    .await
    .map_err(safe_error)
}

pub(super) fn endpoint_update_code_result(
    server_id: ServerId,
    code: EndpointTransitionCode,
) -> EndpointUpdateCodeResult {
    EndpointUpdateCodeResult {
        server_id,
        generation: code.generation(),
        previous_endpoint: code.previous_endpoint().clone(),
        endpoint: code.endpoint().clone(),
        code: code.expose().to_owned(),
    }
}

#[tauri::command]
pub(super) async fn connect_server(
    state: State<'_, AppState>,
    server_id: String,
    persistent_protection: bool,
    transport: TransportPreference,
    network_profile: Option<NetworkProfile>,
    routing: TunnelRoutingPolicy,
) -> Result<LocalTunnelStatus, String> {
    connection_policy::connect_server_with_policy(
        state,
        server_id,
        connection_preferences::ConnectionPreferences {
            android_applications: None,
            manual_mtu: None,
            transport,
            network_profile: network_profile.unwrap_or_default(),
            policy: sirinvpn_tunnel_model::ConnectionPolicy::legacy(persistent_protection),
            routing,
        },
    )
    .await
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
