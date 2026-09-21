//! Membership.

use super::*;

pub(super) async fn membership_handler(
    State(state): State<AppState>,
    Extension(caller): Extension<CallerIdentity>,
) -> Result<Json<ApiEnvelope<MembershipSnapshot>>, ApiError> {
    authorize_device(&state, &caller, false).await?;
    let authorization = require_authorization(&state)?;
    let (mut snapshot, keys) = {
        let current = authorization.read().await;
        let access = authorize_current(&current, &caller, false)?;
        let keys = current
            .devices
            .iter()
            .map(|device| (device.id, device.wireguard_public_key.clone()))
            .collect::<HashMap<_, _>>();
        let mut snapshot = current.snapshot(unix_time());
        if !access.can_manage() {
            let member_id = current
                .device_for_fingerprint(&caller.certificate_fingerprint)
                .ok_or_else(ApiError::forbidden)?
                .member_id;
            snapshot.members.retain(|member| member.id == member_id);
            snapshot.active_invitations.retain(|summary| {
                current.invitations.iter().any(|invitation| {
                    invitation.claims.invitation_id == summary.id
                        && invitation.issued_by == Some(member_id)
                })
            });
            snapshot.port_forwards.retain(|forward| {
                current
                    .devices
                    .iter()
                    .any(|device| device.id == forward.device_id && device.member_id == member_id)
            });
        }
        (snapshot, keys)
    };
    if let Some(activity) =
        super::service_metrics::recent_peer_activity(&state.configuration.interface_name).await
    {
        for device in snapshot
            .members
            .iter_mut()
            .flat_map(|member| &mut member.devices)
        {
            device.recent_handshake = keys
                .get(&device.id)
                .and_then(|key| activity.get(key))
                .copied();
        }
    }
    authorize_device(&state, &caller, false).await?;
    Ok(Json(ApiEnvelope::new(snapshot)))
}

pub(super) async fn create_invitation_handler(
    State(state): State<AppState>,
    Extension(caller): Extension<CallerIdentity>,
    Json(request): Json<InvitationCreateRequest>,
) -> Result<Json<ApiEnvelope<InvitationCreateResponse>>, ApiError> {
    validate_host(&request.endpoint.host).map_err(|error| ApiError::invalid(error.to_string()))?;
    if request.endpoint.wireguard_port == 0 {
        return Err(ApiError::invalid(
            "the invitation endpoint port must be non-zero",
        ));
    }
    if !(60..=7 * 24 * 60 * 60).contains(&request.expires_in_seconds) {
        return Err(ApiError::invalid(
            "invitation lifetime must be between 60 seconds and 7 days",
        ));
    }
    let member_name = validate_display_name(&request.member_name)
        .map_err(|error| ApiError::invalid(error.to_string()))?;
    let device_name = validate_display_name(&request.device_name)
        .map_err(|error| ApiError::invalid(error.to_string()))?;
    validate_token_hash(&request.token_hash)?;
    validate_wireguard_public_key(&request.bootstrap_wireguard_public_key)
        .map_err(|error| ApiError::invalid(error.to_string()))?;
    let bootstrap_fingerprint =
        certificate_fingerprint(&request.bootstrap_management_certificate_pem)
            .map_err(|error| ApiError::invalid(error.to_string()))?;

    let authorization = require_authorization(&state)?;
    let mut current = authorization.write().await;
    let issuer_id = current
        .device_for_fingerprint(&caller.certificate_fingerprint)
        .ok_or_else(ApiError::forbidden)?
        .member_id;
    let caller = authorize_current(&current, &caller, false)?;
    let issuer = current
        .members
        .iter()
        .find(|member| member.id == issuer_id)
        .ok_or_else(ApiError::forbidden)?;
    request
        .member_policy
        .validate()
        .map_err(ApiError::invalid)?;
    if !(1..=100).contains(&request.max_uses) {
        return Err(ApiError::invalid(
            "invitation use limit must be between 1 and 100",
        ));
    }
    if !caller.can_manage() {
        let permitted = match request.target_member_id {
            Some(id) => id == issuer_id && issuer.policy.add_own_devices,
            None => {
                issuer.policy.invite_members && request.member_policy.is_subset_of(&issuer.policy)
            }
        };
        if !permitted || request.administrator {
            return Err(ApiError::forbidden());
        }
    }
    ensure_active_endpoint_authority(&current)?;
    if current.server_id != request.server_id {
        return Err(ApiError::conflict(
            "the invitation request belongs to a different server profile",
        ));
    }
    let now = unix_time();
    let mut next = current.clone();
    next.prune_expired(now);
    if next
        .endpoint_transition
        .as_ref()
        .is_some_and(|transition| request.endpoint != transition.claims.endpoint)
    {
        return Err(ApiError::conflict(
            "this device uses a stale server endpoint; apply the current signed endpoint update before creating invitations",
        ));
    }
    let target = match request.target_member_id {
        Some(member_id) => Some(
            next.members
                .iter()
                .find(|member| member.id == member_id)
                .cloned()
                .ok_or_else(|| {
                    ApiError::new(
                        StatusCode::NOT_FOUND,
                        ErrorCode::InvalidInput,
                        "invitation target member was not found",
                    )
                })?,
        ),
        None => None,
    };
    if let Some(target) = &target {
        if !request.member_policy.is_default()
            || (target.role == ServerRole::Owner && request.max_uses > 1)
        {
            return Err(ApiError::invalid(
                "device invitations inherit existing member policy; owner invitations are single use",
            ));
        }
        next.ensure_device_capacity(target.id)
            .map_err(|error| ApiError::conflict(error.to_string()))?;
        if target.suspended {
            return Err(ApiError::conflict(
                "reactivate this member before inviting another device",
            ));
        }
        if target.name != member_name || target.administrator != request.administrator {
            return Err(ApiError::conflict(
                "invitation target changed; refresh membership and try again",
            ));
        }
        if !can_manage_member(caller, target.role, target.administrator)
            && !(target.id == issuer_id && target.policy.add_own_devices)
        {
            return Err(ApiError::forbidden());
        }
    } else if request.administrator && !caller.is_owner() {
        return Err(ApiError::forbidden());
    }
    if next.devices.iter().any(|device| {
        device.wireguard_public_key == request.bootstrap_wireguard_public_key
            || device.certificate_fingerprint == bootstrap_fingerprint
    }) || next.invitations.iter().any(|invitation| {
        invitation.claims.bootstrap_wireguard_public_key == request.bootstrap_wireguard_public_key
            || certificate_fingerprint(&invitation.claims.bootstrap_management_certificate_pem)
                .is_ok_and(|fingerprint| fingerprint == bootstrap_fingerprint)
    }) || next.enrollment_receipts.iter().any(|receipt| {
        receipt.bootstrap_wireguard_public_key == request.bootstrap_wireguard_public_key
            || receipt.bootstrap_certificate_fingerprint == bootstrap_fingerprint
    }) {
        return Err(ApiError::conflict(
            "the temporary invitation identity is already in use",
        ));
    }

    let claims = InvitationClaims {
        recipient_names: request.recipient_names,
        schema_version: if !state.configuration.alternate_endpoint_hosts.is_empty()
            || state.configuration.endpoint_discovery_port.is_some()
        {
            3
        } else if request.max_uses != 1 || !request.member_policy.is_default() {
            2
        } else {
            1
        },
        invitation_id: InvitationId::new(),
        server_id: current.server_id,
        server_name: state.configuration.server_name.clone(),
        endpoint: request.endpoint,
        alternate_endpoint_hosts: state.configuration.alternate_endpoint_hosts.clone(),
        endpoint_discovery_port: state.configuration.endpoint_discovery_port,
        endpoint_generation: next.endpoint_generation(),
        server_tunnel_address: state.configuration.server_tunnel_address,
        management_port: state.configuration.management_port,
        server_wireguard_public_key: state.configuration.wireguard_public_key.clone(),
        pinned_server_certificate_pem: fs::read_to_string(&state.paths.tls_certificate)
            .map_err(|_| ApiError::internal())?,
        obfuscated_udp: state.configuration.obfuscated_udp.clone(),
        tcp_fallback: state.configuration.tcp_fallback.clone(),
        tls_like: state.configuration.tls_like.clone(),
        member_id: MemberId::new(),
        target_member_id: target.as_ref().map(|member| member.id),
        target_role: target.as_ref().map(|member| member.role),
        device_id: DeviceId::new(),
        member_name,
        device_name,
        role: ServerRole::Member,
        administrator: request.administrator,
        max_uses: request.max_uses,
        member_policy: request.member_policy,
        client_tunnel_address: next
            .allocate_member_address()
            .map_err(|_| ApiError::conflict("the member address pool is exhausted"))?,
        bootstrap_tunnel_address: next
            .allocate_bootstrap_address()
            .map_err(|_| ApiError::conflict("the invitation address pool is exhausted"))?,
        expires_at_unix: now + u64::from(request.expires_in_seconds),
        token_hash: request.token_hash,
        bootstrap_wireguard_public_key: request.bootstrap_wireguard_public_key,
        bootstrap_management_certificate_pem: request.bootstrap_management_certificate_pem,
    };
    let signature =
        sign_claims(&state.paths.tls_private_key, &claims).map_err(|_| ApiError::internal())?;
    let response = InvitationCreateResponse {
        claims: claims.clone(),
        signature: signature.clone(),
    };
    next.invitations.push(InvitationRecord {
        claims,
        signature,
        issued_by: Some(issuer_id),
        uses_consumed: 0,
    });
    next.schema_version = next.required_schema_version();
    commit_authorization(&state, &mut current, next).await?;
    Ok(Json(ApiEnvelope::new(response)))
}

pub(super) async fn cancel_invitation_handler(
    State(state): State<AppState>,
    Extension(caller): Extension<CallerIdentity>,
    AxumPath(invitation_id): AxumPath<String>,
) -> Result<Json<ApiEnvelope<()>>, ApiError> {
    let invitation_id = invitation_id
        .parse::<InvitationId>()
        .map_err(|_| ApiError::invalid("invitation identifier is invalid"))?;
    let authorization = require_authorization(&state)?;
    let mut current = authorization.write().await;
    let issuer_id = current
        .device_for_fingerprint(&caller.certificate_fingerprint)
        .ok_or_else(ApiError::forbidden)?
        .member_id;
    let caller = authorize_current(&current, &caller, false)?;
    ensure_active_endpoint_authority(&current)?;
    let mut next = current.clone();
    let invitation = next
        .invitations
        .iter()
        .find(|invitation| invitation.claims.invitation_id == invitation_id)
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::NOT_FOUND,
                ErrorCode::InvalidInput,
                "active invitation was not found",
            )
        })?;
    if !can_manage_member(
        caller,
        invitation
            .claims
            .target_role
            .unwrap_or(invitation.claims.role),
        invitation.claims.administrator,
    ) && invitation.issued_by != Some(issuer_id)
    {
        return Err(ApiError::forbidden());
    }
    let before = next.invitations.len();
    next.invitations
        .retain(|invitation| invitation.claims.invitation_id != invitation_id);
    next.schema_version = next.required_schema_version();
    debug_assert_ne!(before, next.invitations.len());
    commit_authorization(&state, &mut current, next).await?;
    Ok(Json(ApiEnvelope::new(())))
}

pub(super) async fn rename_device_handler(
    State(state): State<AppState>,
    Extension(caller): Extension<CallerIdentity>,
    AxumPath(device_id): AxumPath<String>,
    Json(request): Json<RenameDeviceRequest>,
) -> Result<Json<ApiEnvelope<MembershipSnapshot>>, ApiError> {
    let device_id = device_id
        .parse::<DeviceId>()
        .map_err(|_| ApiError::invalid("device identifier is invalid"))?;
    let name = validate_display_name(&request.name)
        .map_err(|error| ApiError::invalid(error.to_string()))?;
    let authorization = require_authorization(&state)?;
    let mut current = authorization.write().await;
    let caller = authorize_current(&current, &caller, true)?;
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
    if !can_manage_member(caller, target_member.role, target_member.administrator) {
        return Err(ApiError::forbidden());
    }
    let mut next = current.clone();
    let device = next
        .devices
        .iter_mut()
        .find(|device| device.id == device_id)
        .ok_or_else(ApiError::internal)?;
    device.name = name;
    let snapshot = next.snapshot(unix_time());
    commit_authorization(&state, &mut current, next).await?;
    Ok(Json(ApiEnvelope::new(snapshot)))
}

pub(super) async fn revoke_device_handler(
    State(state): State<AppState>,
    Extension(caller): Extension<CallerIdentity>,
    AxumPath(device_id): AxumPath<String>,
) -> Result<Json<ApiEnvelope<MembershipSnapshot>>, ApiError> {
    let device_id = device_id
        .parse::<DeviceId>()
        .map_err(|_| ApiError::invalid("device identifier is invalid"))?;
    let authorization = require_authorization(&state)?;
    let mut current = authorization.write().await;
    let caller = authorize_current(&current, &caller, true)?;
    ensure_active_endpoint_authority(&current)?;
    let target = current
        .devices
        .iter()
        .find(|device| device.id == device_id)
        .cloned()
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
    if !can_manage_member(caller, target_member.role, target_member.administrator) {
        return Err(ApiError::forbidden());
    }
    if target_member.role == ServerRole::Owner
        && current
            .devices
            .iter()
            .filter(|device| device.member_id == target.member_id)
            .count()
            <= 1
    {
        return Err(ApiError::conflict(
            "the last owner device cannot be revoked",
        ));
    }
    let mut next = current.clone();
    next.remove_device_and_dependents(device_id, target.member_id);
    let snapshot = next.snapshot(unix_time());
    commit_authorization(&state, &mut current, next).await?;
    Ok(Json(ApiEnvelope::new(snapshot)))
}

pub(super) async fn update_member_access_handler(
    State(state): State<AppState>,
    Extension(caller): Extension<CallerIdentity>,
    AxumPath(member_id): AxumPath<String>,
    Json(request): Json<MemberAccessUpdateRequest>,
) -> Result<Json<ApiEnvelope<MembershipSnapshot>>, ApiError> {
    let member_id = member_id
        .parse::<MemberId>()
        .map_err(|_| ApiError::invalid("member identifier is invalid"))?;
    let authorization = require_authorization(&state)?;
    let mut current = authorization.write().await;
    let caller = authorize_current(&current, &caller, true)?;
    if !caller.is_owner() {
        return Err(ApiError::forbidden());
    }
    ensure_active_endpoint_authority(&current)?;
    let target = current
        .members
        .iter()
        .find(|member| member.id == member_id)
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::NOT_FOUND,
                ErrorCode::InvalidInput,
                "member was not found",
            )
        })?;
    if target.role == ServerRole::Owner {
        return Err(ApiError::conflict(
            "the owner access level cannot be changed",
        ));
    }
    if target.administrator == request.administrator {
        return Ok(Json(ApiEnvelope::new(current.snapshot(unix_time()))));
    }
    if current.invitations.iter().any(|invitation| {
        invitation.claims.target_member_id == Some(member_id)
            || (invitation.claims.target_member_id.is_none()
                && invitation.claims.member_id == member_id)
    }) || current
        .enrollment_receipts
        .iter()
        .any(|receipt| receipt.result.member_id == member_id)
    {
        return Err(ApiError::conflict(
            "wait for recent enrollment handoffs and cancel active device invitations before changing access",
        ));
    }
    let mut next = current.clone();
    let target = next
        .members
        .iter_mut()
        .find(|member| member.id == member_id)
        .ok_or_else(ApiError::internal)?;
    target.administrator = request.administrator;
    if !request.administrator {
        next.recovery_policy
            .administrator_member_ids
            .retain(|id| *id != member_id);
        if next
            .recovery_key
            .as_ref()
            .is_some_and(|key| key.claims.issuer_member_id == member_id)
        {
            next.recovery_key = None;
        }
    }
    next.invitations
        .retain(|invitation| invitation.issued_by != Some(member_id));
    let snapshot = next.snapshot(unix_time());
    commit_authorization(&state, &mut current, next).await?;
    Ok(Json(ApiEnvelope::new(snapshot)))
}

pub(super) async fn transfer_ownership_handler(
    State(state): State<AppState>,
    Extension(caller): Extension<CallerIdentity>,
    Json(request): Json<OwnershipTransferRequest>,
) -> Result<Json<ApiEnvelope<MembershipSnapshot>>, ApiError> {
    let authorization = require_authorization(&state)?;
    let mut current = authorization.write().await;
    ensure_active_endpoint_authority(&current)?;
    let caller_is_owner = current
        .device_for_fingerprint(&caller.certificate_fingerprint)
        .and_then(|device| current.access_for_device(device))
        .is_some_and(|access| access.role == ServerRole::Owner);
    if !caller_is_owner {
        return Err(ApiError::forbidden());
    }
    let mut next = current.clone();
    next.prune_expired(unix_time());
    next.transfer_ownership(request.destination_device_id)
        .map_err(|error| ApiError::conflict(error.to_string()))?;
    let snapshot = next.snapshot(unix_time());
    commit_authorization(&state, &mut current, next).await?;
    Ok(Json(ApiEnvelope::new(snapshot)))
}
