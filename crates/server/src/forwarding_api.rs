//! Forwarding api.

use super::*;

pub(super) async fn update_device_peer_communication_handler(
    State(state): State<AppState>,
    Extension(caller): Extension<CallerIdentity>,
    AxumPath(device_id): AxumPath<String>,
    Json(request): Json<DevicePeerCommunicationUpdateRequest>,
) -> Result<Json<ApiEnvelope<MembershipSnapshot>>, ApiError> {
    let device_id = device_id
        .parse::<DeviceId>()
        .map_err(|_| ApiError::invalid("device identifier is invalid"))?;
    let authorization = require_authorization(&state)?;
    let mut current = authorization.write().await;
    let caller = authorize_current(&current, &caller, false)?;
    ensure_active_endpoint_authority(&current)?;
    let target = current
        .devices
        .iter()
        .find(|device| device.id == device_id)
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::NOT_FOUND,
                ErrorCode::InvalidInput,
                "device was not found",
            )
        })?;
    let target_member = current
        .members
        .iter()
        .find(|member| member.id == target.member_id)
        .ok_or_else(ApiError::internal)?;
    if !can_manage_member(caller, target_member.role, target_member.administrator)
        && !caller_member(&current, caller).is_some_and(|member| {
            member.id == target_member.id && member.policy.manage_own_peer_communication
        })
    {
        return Err(ApiError::forbidden());
    }
    if target.peer_communication_enabled == request.enabled {
        return Ok(Json(ApiEnvelope::new(filtered_snapshot(&current, caller))));
    }
    let mut next = current.clone();
    next.set_device_peer_communication(device_id, request.enabled)
        .map_err(|_| ApiError::internal())?;
    let snapshot = filtered_snapshot(&next, caller);
    commit_authorization(&state, &mut current, next).await?;
    Ok(Json(ApiEnvelope::new(snapshot)))
}

pub(super) async fn create_port_forward_handler(
    State(state): State<AppState>,
    Extension(caller): Extension<CallerIdentity>,
    Json(request): Json<PortForwardCreateRequest>,
) -> Result<Json<ApiEnvelope<MembershipSnapshot>>, ApiError> {
    let operational = state.operational_configuration.as_ref().ok_or_else(|| {
        ApiError::conflict("repair this SirinVPN server before managing port forwards")
    })?;
    let forward = PortForward {
        protocol: request.protocol,
        public_port: request.public_port,
        device_id: request.device_id,
        device_port: request.device_port,
    };
    validate_port_forward(&state.configuration, operational, &forward)
        .map_err(|error| ApiError::invalid(error.to_string()))?;

    let authorization = require_authorization(&state)?;
    let mut current = authorization.write().await;
    let caller = authorize_current(&current, &caller, false)?;
    ensure_active_endpoint_authority(&current)?;
    let target = current
        .devices
        .iter()
        .find(|device| device.id == forward.device_id)
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::NOT_FOUND,
                ErrorCode::InvalidInput,
                "device was not found",
            )
        })?;
    let target_member = current
        .members
        .iter()
        .find(|member| member.id == target.member_id)
        .ok_or_else(ApiError::internal)?;
    if !can_manage_member(caller, target_member.role, target_member.administrator)
        && !caller_member(&current, caller).is_some_and(|member| {
            member.id == target_member.id && member.policy.manage_own_port_forwards
        })
    {
        return Err(ApiError::forbidden());
    }
    if target_member.suspended {
        return Err(ApiError::conflict(
            "reactivate this member before adding a port forward",
        ));
    }
    if current.port_forwards.len() >= MAX_PORT_FORWARDS {
        return Err(ApiError::conflict(
            "the port-forward limit has been reached",
        ));
    }
    if current.port_forwards.iter().any(|existing| {
        existing.protocol == forward.protocol && existing.public_port == forward.public_port
    }) {
        return Err(ApiError::conflict(
            "that public protocol and port is already forwarded",
        ));
    }

    let mut next = current.clone();
    next.add_port_forward(forward)
        .map_err(|_| ApiError::internal())?;
    let snapshot = filtered_snapshot(&next, caller);
    commit_authorization(&state, &mut current, next).await?;
    Ok(Json(ApiEnvelope::new(snapshot)))
}

pub(super) async fn delete_port_forward_handler(
    State(state): State<AppState>,
    Extension(caller): Extension<CallerIdentity>,
    AxumPath((protocol, public_port)): AxumPath<(String, String)>,
) -> Result<Json<ApiEnvelope<MembershipSnapshot>>, ApiError> {
    if state.operational_configuration.is_none() {
        return Err(ApiError::conflict(
            "repair this SirinVPN server before managing port forwards",
        ));
    }
    let protocol = parse_port_forward_protocol(&protocol)?;
    let public_port = public_port
        .parse::<u16>()
        .map_err(|_| ApiError::invalid("public port is invalid"))?;
    let authorization = require_authorization(&state)?;
    let mut current = authorization.write().await;
    let caller = authorize_current(&current, &caller, false)?;
    ensure_active_endpoint_authority(&current)?;
    let forward = current
        .port_forwards
        .iter()
        .find(|forward| forward.protocol == protocol && forward.public_port == public_port)
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::NOT_FOUND,
                ErrorCode::InvalidInput,
                "port forward was not found",
            )
        })?;
    let target = current
        .devices
        .iter()
        .find(|device| device.id == forward.device_id)
        .ok_or_else(ApiError::internal)?;
    let target_member = current
        .members
        .iter()
        .find(|member| member.id == target.member_id)
        .ok_or_else(ApiError::internal)?;
    if !can_manage_member(caller, target_member.role, target_member.administrator)
        && !caller_member(&current, caller).is_some_and(|member| {
            member.id == target_member.id && member.policy.manage_own_port_forwards
        })
    {
        return Err(ApiError::forbidden());
    }

    let mut next = current.clone();
    next.remove_port_forward(protocol, public_port)
        .map_err(|_| ApiError::internal())?;
    let snapshot = filtered_snapshot(&next, caller);
    commit_authorization(&state, &mut current, next).await?;
    Ok(Json(ApiEnvelope::new(snapshot)))
}

pub(super) fn parse_port_forward_protocol(value: &str) -> Result<PortForwardProtocol, ApiError> {
    match value {
        "tcp" => Ok(PortForwardProtocol::Tcp),
        "udp" => Ok(PortForwardProtocol::Udp),
        _ => Err(ApiError::invalid("port-forward protocol is invalid")),
    }
}
