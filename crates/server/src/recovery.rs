//! Owner recovery consumes a separate offline identity and replaces lost Owner devices.
use super::*;
use sirinvpn_protocol::{
    RecoveryId, RecoveryKeyClaims, RecoveryKeyCreateRequest, RecoveryKeyResponse, RecoveryPolicy,
    RecoveryRedeemRequest, RecoverySettings,
};

pub(super) async fn settings_handler(
    State(state): State<AppState>,
    Extension(identity): Extension<CallerIdentity>,
) -> Result<Json<ApiEnvelope<RecoverySettings>>, ApiError> {
    let authorization = require_authorization(&state)?;
    let current = authorization.read().await;
    let caller = authorize_current(&current, &identity, true)?;
    let member = caller_member(&current, caller).ok_or_else(ApiError::forbidden)?;
    Ok(Json(ApiEnvelope::new(
        current
            .recovery_settings(member)
            .map_err(|_| ApiError::internal())?,
    )))
}

pub(super) async fn policy_handler(
    State(state): State<AppState>,
    Extension(identity): Extension<CallerIdentity>,
    Json(policy): Json<RecoveryPolicy>,
) -> Result<Json<ApiEnvelope<RecoverySettings>>, ApiError> {
    let authorization = require_authorization(&state)?;
    let mut current = authorization.write().await;
    let caller = authorize_current(&current, &identity, true)?;
    if !caller.is_owner() {
        return Err(ApiError::forbidden());
    }
    ensure_active_endpoint_authority(&current)?;
    if policy.administrator_member_ids.len() > 32
        || policy
            .administrator_member_ids
            .iter()
            .collect::<HashSet<_>>()
            .len()
            != policy.administrator_member_ids.len()
        || policy.administrator_member_ids.iter().any(|id| {
            !current.members.iter().any(|member| {
                member.id == *id && member.role == ServerRole::Member && member.administrator
            })
        })
    {
        return Err(ApiError::invalid(
            "select unique current administrators for Owner recovery",
        ));
    }
    let mut next = current.clone();
    next.recovery_policy = policy;
    if next.recovery_key.as_ref().is_some_and(|key| {
        key.claims.issuer_member_id != key.claims.owner_member_id
            && !next
                .recovery_policy
                .administrator_member_ids
                .contains(&key.claims.issuer_member_id)
    }) {
        next.recovery_key = None;
    }
    let result = next
        .recovery_settings(caller_member(&next, caller).ok_or_else(ApiError::forbidden)?)
        .map_err(|_| ApiError::internal())?;
    commit_authorization(&state, &mut current, next).await?;
    Ok(Json(ApiEnvelope::new(result)))
}

pub(super) async fn create_key_handler(
    State(state): State<AppState>,
    Extension(identity): Extension<CallerIdentity>,
    Json(request): Json<RecoveryKeyCreateRequest>,
) -> Result<Json<ApiEnvelope<RecoveryKeyResponse>>, ApiError> {
    if !request.confirmed {
        return Err(ApiError::invalid(
            "confirm that this key can replace every Owner device",
        ));
    }
    validate_host(&request.endpoint.host).map_err(|error| ApiError::invalid(error.to_string()))?;
    validate_wireguard_public_key(&request.recovery_wireguard_public_key)
        .map_err(|error| ApiError::invalid(error.to_string()))?;
    let fingerprint = certificate_fingerprint(&request.recovery_management_certificate_pem)
        .map_err(|error| ApiError::invalid(error.to_string()))?;
    let authorization = require_authorization(&state)?;
    let mut current = authorization.write().await;
    let caller = authorize_current(&current, &identity, true)?;
    let member = caller_member(&current, caller).ok_or_else(ApiError::forbidden)?;
    if !current.can_issue_recovery(member) {
        return Err(ApiError::forbidden());
    }
    let issuer_member_id = member.id;
    ensure_active_endpoint_authority(&current)?;
    if request.server_id != current.server_id
        || request.endpoint_generation != current.endpoint_generation()
        || request.endpoint.wireguard_port != state.configuration.wireguard_port
        || current
            .endpoint_transition
            .as_ref()
            .is_some_and(|transition| transition.claims.endpoint != request.endpoint)
        || request.recovery_id.0.is_nil()
    {
        return Err(ApiError::conflict(
            "refresh the current server endpoint before creating a recovery key",
        ));
    }
    // A lost setup response can be retried using the same local recovery identity.
    if let Some(existing) = &current.recovery_key
        && existing.claims.recovery_id == request.recovery_id
        && existing.claims.recovery_wireguard_public_key == request.recovery_wireguard_public_key
        && existing.claims.recovery_management_certificate_pem
            == request.recovery_management_certificate_pem
    {
        return Ok(Json(ApiEnvelope::new(existing.clone())));
    }
    if current
        .recovery_key
        .as_ref()
        .map(|key| key.claims.recovery_id)
        != request.replace_recovery_id
    {
        return Err(ApiError::conflict(
            "the active recovery key changed; refresh before replacing it",
        ));
    }
    let mut next = current.clone();
    next.prune_expired(unix_time());
    if next.recovery_receipt.is_some() {
        return Err(ApiError::conflict(
            "wait one minute for the current recovery enrollment to finish",
        ));
    }
    let address = IpAddr::V4(Ipv4Addr::new(10, 77, 0, 254));
    if next
        .invitations
        .iter()
        .any(|grant| grant.claims.bootstrap_tunnel_address == address)
        || next
            .enrollment_receipts
            .iter()
            .any(|receipt| receipt.bootstrap_tunnel_address == address)
    {
        return Err(ApiError::conflict(
            "an older invitation is using the recovery address; cancel it or wait for its enrollment to finish",
        ));
    }
    if current.devices.iter().any(|device| {
        device.wireguard_public_key == request.recovery_wireguard_public_key
            || device.certificate_fingerprint == fingerprint
    }) {
        return Err(ApiError::invalid(
            "generate a separate local recovery identity",
        ));
    }
    let owner_member_id = current
        .members
        .iter()
        .find(|member| member.role == ServerRole::Owner)
        .ok_or_else(ApiError::internal)?
        .id;
    let claims = RecoveryKeyClaims {
        schema_version: if !state.configuration.alternate_endpoint_hosts.is_empty()
            || state.configuration.endpoint_discovery_port.is_some()
        {
            2
        } else {
            1
        },
        alternate_endpoint_hosts: state.configuration.alternate_endpoint_hosts.clone(),
        endpoint_discovery_port: state.configuration.endpoint_discovery_port,
        recovery_id: request.recovery_id,
        server_id: current.server_id,
        owner_member_id,
        issuer_member_id,
        server_name: state.configuration.server_name.clone(),
        endpoint: request.endpoint,
        endpoint_generation: current.endpoint_generation(),
        server_tunnel_address: state.configuration.server_tunnel_address,
        management_port: state.configuration.management_port,
        server_wireguard_public_key: state.configuration.wireguard_public_key.clone(),
        pinned_server_certificate_pem: fs::read_to_string(&state.paths.tls_certificate)
            .map_err(|_| ApiError::internal())?,
        obfuscated_udp: state.configuration.obfuscated_udp.clone(),
        tcp_fallback: state.configuration.tcp_fallback.clone(),
        tls_like: state.configuration.tls_like.clone(),
        recovery_tunnel_address: address,
        recovery_wireguard_public_key: request.recovery_wireguard_public_key,
        recovery_management_certificate_pem: request.recovery_management_certificate_pem,
    };
    let signature = authorization::sign_recovery_claims(&state.paths.tls_private_key, &claims)
        .map_err(|_| ApiError::internal())?;
    let response = RecoveryKeyResponse { claims, signature };
    next.recovery_key = Some(response.clone());
    commit_authorization(&state, &mut current, next).await?;
    Ok(Json(ApiEnvelope::new(response)))
}

pub(super) async fn revoke_key_handler(
    State(state): State<AppState>,
    Extension(identity): Extension<CallerIdentity>,
    AxumPath(id): AxumPath<String>,
) -> Result<Json<ApiEnvelope<RecoverySettings>>, ApiError> {
    let id = id
        .parse::<RecoveryId>()
        .map_err(|_| ApiError::invalid("recovery identifier is invalid"))?;
    let authorization = require_authorization(&state)?;
    let mut current = authorization.write().await;
    let caller = authorize_current(&current, &identity, true)?;
    if !caller.is_owner() {
        return Err(ApiError::forbidden());
    }
    ensure_active_endpoint_authority(&current)?;
    if current
        .recovery_key
        .as_ref()
        .is_some_and(|key| key.claims.recovery_id != id)
    {
        return Err(ApiError::conflict(
            "the recovery key changed; refresh before revoking it",
        ));
    }
    let mut next = current.clone();
    next.recovery_key = None;
    let result = next
        .recovery_settings(caller_member(&next, caller).ok_or_else(ApiError::forbidden)?)
        .map_err(|_| ApiError::internal())?;
    commit_authorization(&state, &mut current, next).await?;
    Ok(Json(ApiEnvelope::new(result)))
}

pub(super) async fn enroll_handler(
    State(state): State<AppState>,
    Extension(identity): Extension<CallerIdentity>,
    Json(request): Json<RecoveryRedeemRequest>,
) -> Result<Json<ApiEnvelope<EnrollmentResult>>, ApiError> {
    if !request.confirmed {
        return Err(ApiError::invalid(
            "confirm replacing every Owner device and consuming this recovery key",
        ));
    }
    let authorization = require_authorization(&state)?;
    let mut current = authorization.write().await;
    ensure_active_endpoint_authority(&current)?;
    let now = unix_time();
    let response = current
        .recovery_authorization(now)
        .ok_or_else(ApiError::forbidden)?
        .clone();
    if response.claims.recovery_id != request.recovery_id
        || certificate_fingerprint(&response.claims.recovery_management_certificate_pem)
            .map_err(|_| ApiError::internal())?
            != identity.certificate_fingerprint
    {
        return Err(ApiError::forbidden());
    }
    let rate_id = InvitationId(request.recovery_id.0);
    if redemption_is_limited(&state, rate_id, now) {
        return Err(ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            ErrorCode::RateLimited,
            "too many failed recovery attempts; try again shortly",
        ));
    }
    if let Some(receipt) = &current.recovery_receipt {
        if receipt.device_wireguard_public_key == request.device_wireguard_public_key
            && receipt.device_management_certificate_pem
                == request.device_management_certificate_pem
        {
            return Ok(Json(ApiEnvelope::new(receipt.result.clone())));
        }
        record_redemption_failure(&state, rate_id, now);
        return Err(ApiError::conflict(
            "this recovery key has already enrolled a different Owner identity",
        ));
    }
    let name = validate_display_name(&request.device_name)
        .map_err(|error| ApiError::invalid(error.to_string()))?;
    validate_wireguard_public_key(&request.device_wireguard_public_key)
        .map_err(|error| ApiError::invalid(error.to_string()))?;
    let fingerprint = certificate_fingerprint(&request.device_management_certificate_pem)
        .map_err(|error| ApiError::invalid(error.to_string()))?;
    if fingerprint == identity.certificate_fingerprint
        || request.device_wireguard_public_key == response.claims.recovery_wireguard_public_key
        || current.devices.iter().any(|device| {
            device.wireguard_public_key == request.device_wireguard_public_key
                || device.certificate_fingerprint == fingerprint
        })
    {
        record_redemption_failure(&state, rate_id, now);
        return Err(ApiError::invalid(
            "recovery requires a new permanent identity generated on this device",
        ));
    }
    let owner_id = response.claims.owner_member_id;
    let mut next = current.clone();
    let old_devices: HashSet<_> = next
        .devices
        .iter()
        .filter(|device| device.member_id == owner_id)
        .map(|device| device.id)
        .collect();
    let previous_address = next
        .devices
        .iter()
        .find(|device| device.member_id == owner_id)
        .map(|device| device.client_tunnel_address);
    next.devices
        .retain(|device| !old_devices.contains(&device.id));
    next.invitations.retain(|grant| {
        grant.claims.target_member_id != Some(owner_id) && grant.issued_by != Some(owner_id)
    });
    next.enrollment_receipts
        .retain(|receipt| !old_devices.contains(&receipt.result.device_id));
    next.key_rotations
        .retain(|rotation| !old_devices.contains(&rotation.device_id));
    next.port_forwards
        .retain(|forward| !old_devices.contains(&forward.device_id));
    let address = previous_address
        .map(Ok)
        .unwrap_or_else(|| next.allocate_member_address())
        .map_err(|_| ApiError::conflict("the member address pool is exhausted"))?;
    let device_id = DeviceId::new();
    next.devices.push(DeviceRecord {
        id: device_id,
        member_id: owner_id,
        name,
        client_tunnel_address: address,
        wireguard_public_key: request.device_wireguard_public_key.clone(),
        management_certificate_pem: request.device_management_certificate_pem.clone(),
        certificate_fingerprint: fingerprint,
        peer_communication_enabled: false,
    });
    let result = EnrollmentResult {
        names: None,
        alternate_endpoint_hosts: state.configuration.alternate_endpoint_hosts.clone(),
        endpoint_discovery_port: state.configuration.endpoint_discovery_port,
        server_id: next.server_id,
        member_id: owner_id,
        device_id,
        role: ServerRole::Owner,
        administrator: false,
        server_name: state.configuration.server_name.clone(),
        endpoint: next.endpoint_transition.as_ref().map_or_else(
            || response.claims.endpoint.clone(),
            |transition| transition.claims.endpoint.clone(),
        ),
        endpoint_generation: next.endpoint_generation(),
        client_tunnel_address: address,
        server_tunnel_address: state.configuration.server_tunnel_address,
        server_wireguard_public_key: state.configuration.wireguard_public_key.clone(),
        pinned_server_certificate_pem: response.claims.pinned_server_certificate_pem.clone(),
        obfuscated_udp: state.configuration.obfuscated_udp.clone(),
        tcp_fallback: state.configuration.tcp_fallback.clone(),
        tls_like: state.configuration.tls_like.clone(),
        ipv6_tunnel_enabled: state.configuration.ipv6_tunnel_enabled,
    };
    next.recovery_key = None;
    next.recovery_policy = RecoveryPolicy::default();
    next.recovery_receipt = Some(authorization::RecoveryReceipt {
        response,
        device_wireguard_public_key: request.device_wireguard_public_key,
        device_management_certificate_pem: request.device_management_certificate_pem,
        result: result.clone(),
        expires_at_unix: now + ENROLLMENT_HANDOFF_SECONDS,
    });
    commit_authorization(&state, &mut current, next).await?;
    clear_redemption_failures(&state, rate_id);
    Ok(Json(ApiEnvelope::new(result)))
}
