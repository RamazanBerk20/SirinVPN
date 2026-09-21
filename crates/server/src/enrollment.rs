//! Enrollment.

use super::*;

pub(super) async fn prepare_key_rotation_handler(
    State(state): State<AppState>,
    Extension(caller): Extension<CallerIdentity>,
    Json(request): Json<KeyRotationPrepareRequest>,
) -> Result<Json<ApiEnvelope<KeyRotationPrepareResponse>>, ApiError> {
    authorize_device(&state, &caller, false).await?;
    validate_wireguard_public_key(&request.new_wireguard_public_key)
        .map_err(|error| ApiError::invalid(error.to_string()))?;
    certificate_fingerprint(&request.new_management_certificate_pem)
        .map_err(|_| ApiError::invalid("the new management certificate is invalid"))?;
    let authorization = require_authorization(&state)?;
    let mut current = authorization.write().await;
    ensure_active_endpoint_authority(&current)?;
    authorize_current(&current, &caller, false)?;
    let mut next = current.clone();
    let now = unix_time();
    next.prune_expired(now);
    let response = next
        .prepare_key_rotation(&caller.certificate_fingerprint, &request, now)
        .map_err(|error| ApiError::conflict(error.to_string()))?;
    commit_authorization(&state, &mut current, next).await?;
    Ok(Json(ApiEnvelope::new(response)))
}

pub(super) async fn commit_key_rotation_handler(
    State(state): State<AppState>,
    Extension(caller): Extension<CallerIdentity>,
    AxumPath(rotation_id): AxumPath<String>,
) -> Result<Json<ApiEnvelope<KeyRotationCommitResponse>>, ApiError> {
    let rotation_id = rotation_id
        .parse::<KeyRotationId>()
        .map_err(|_| ApiError::invalid("key rotation identifier is invalid"))?;
    let authorization = require_authorization(&state)?;
    let mut current = authorization.write().await;
    ensure_active_endpoint_authority(&current)?;
    let mut next = current.clone();
    let now = unix_time();
    next.prune_expired(now);
    let response = next
        .commit_key_rotation(rotation_id, &caller.certificate_fingerprint, now)
        .map_err(|_| ApiError::forbidden())?;
    commit_authorization(&state, &mut current, next).await?;
    Ok(Json(ApiEnvelope::new(response)))
}

pub(super) async fn cancel_key_rotation_handler(
    State(state): State<AppState>,
    Extension(caller): Extension<CallerIdentity>,
    AxumPath(rotation_id): AxumPath<String>,
) -> Result<Json<ApiEnvelope<()>>, ApiError> {
    let rotation_id = rotation_id
        .parse::<KeyRotationId>()
        .map_err(|_| ApiError::invalid("key rotation identifier is invalid"))?;
    let authorization = require_authorization(&state)?;
    let mut current = authorization.write().await;
    ensure_active_endpoint_authority(&current)?;
    let mut next = current.clone();
    next.prune_expired(unix_time());
    next.cancel_key_rotation(rotation_id, &caller.certificate_fingerprint)
        .map_err(|_| ApiError::forbidden())?;
    commit_authorization(&state, &mut current, next).await?;
    Ok(Json(ApiEnvelope::new(())))
}

pub(super) async fn enrollment_handler(
    State(state): State<AppState>,
    Extension(caller): Extension<CallerIdentity>,
    Json(request): Json<EnrollmentRequest>,
) -> Result<Json<ApiEnvelope<EnrollmentResult>>, ApiError> {
    let authorization = require_authorization(&state)?;
    let now = unix_time();
    let mut current = authorization.write().await;
    ensure_active_endpoint_authority(&current)?;

    let active_invitation = current
        .invitation_for_fingerprint(&caller.certificate_fingerprint, now)
        .cloned();
    let available_receipt = current.receipt_for_fingerprint(&caller.certificate_fingerprint, now);
    let receipt = current
        .enrollment_receipts
        .iter()
        .find(|receipt| {
            receipt.expires_at_unix > now
                && receipt.bootstrap_certificate_fingerprint == caller.certificate_fingerprint
                && (receipt.claims.max_uses == 1 || enrollment_matches_receipt(&request, receipt))
        })
        .cloned();
    let rate_key = active_invitation
        .as_ref()
        .map(|invitation| invitation.claims.invitation_id)
        .or_else(|| available_receipt.map(|receipt| receipt.invitation_id))
        .ok_or_else(ApiError::forbidden)?;
    if redemption_is_limited(&state, rate_key, now) {
        return Err(ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            ErrorCode::RateLimited,
            "too many failed enrollment attempts; try again shortly",
        ));
    }

    if let Some(receipt) = receipt {
        if enrollment_matches_receipt(&request, &receipt)
            && token_matches(&request.token, &receipt.token_hash)
        {
            let device = current
                .devices
                .iter()
                .find(|device| device.id == receipt.result.device_id)
                .ok_or_else(ApiError::forbidden)?;
            if current.access_for_device(device).is_none() {
                return Err(ApiError::forbidden());
            }
            return Ok(Json(ApiEnvelope::new(receipt.result)));
        }
        record_redemption_failure(&state, rate_key, now);
        return Err(ApiError::conflict(
            "this single-use invitation has already enrolled a different identity",
        ));
    }

    let invitation = active_invitation.ok_or_else(ApiError::forbidden)?;
    if invitation.issued_by.is_some_and(|id| {
        current
            .members
            .iter()
            .find(|member| member.id == id)
            .is_none_or(|member| member.suspended || !member.policy.permits_access_at(now))
    }) {
        return Err(ApiError::forbidden());
    }
    if !invitation.claims.member_policy.permits_access_at(now) {
        return Err(ApiError::conflict(
            "this invitation's member access is currently outside its permitted time",
        ));
    }
    if invitation.claims.expires_at_unix <= now {
        return Err(ApiError::new(
            StatusCode::GONE,
            ErrorCode::InvitationExpired,
            "the invitation has expired",
        ));
    }
    if request.claims != invitation.claims
        || request.signature != invitation.signature
        || !token_matches(&request.token, &invitation.claims.token_hash)
    {
        record_redemption_failure(&state, rate_key, now);
        return Err(ApiError::forbidden());
    }
    let (member_name, device_name) = resolve_enrollment_names(&request)?;
    validate_wireguard_public_key(&request.device_wireguard_public_key)
        .map_err(|error| ApiError::invalid(error.to_string()))?;
    let device_fingerprint = certificate_fingerprint(&request.device_management_certificate_pem)
        .map_err(|error| ApiError::invalid(error.to_string()))?;
    if request.device_wireguard_public_key == invitation.claims.bootstrap_wireguard_public_key
        || device_fingerprint == caller.certificate_fingerprint
        || current.devices.iter().any(|device| {
            device.wireguard_public_key == request.device_wireguard_public_key
                || device.certificate_fingerprint == device_fingerprint
        })
        || current.invitations.iter().any(|candidate| {
            candidate.claims.invitation_id != invitation.claims.invitation_id
                && (candidate.claims.bootstrap_wireguard_public_key
                    == request.device_wireguard_public_key
                    || certificate_fingerprint(
                        &candidate.claims.bootstrap_management_certificate_pem,
                    )
                    .is_ok_and(|fingerprint| fingerprint == device_fingerprint))
        })
        || current.enrollment_receipts.iter().any(|receipt| {
            receipt.bootstrap_wireguard_public_key == request.device_wireguard_public_key
                || receipt.bootstrap_certificate_fingerprint == device_fingerprint
        })
    {
        record_redemption_failure(&state, rate_key, now);
        return Err(ApiError::conflict(
            "the permanent device identity must be new and generated locally",
        ));
    }

    let target_member = invitation
        .claims
        .target_member_id
        .map(|member_id| {
            current
                .members
                .iter()
                .find(|member| member.id == member_id)
                .cloned()
                .ok_or_else(|| ApiError::conflict("the invitation target member no longer exists"))
        })
        .transpose()?;
    if target_member.as_ref().is_some_and(|member| {
        member.suspended
            || invitation.claims.target_role != Some(member.role)
            || invitation.claims.member_name != member.name
            || invitation.claims.administrator != member.administrator
    }) {
        return Err(ApiError::conflict(
            "the invitation target changed; create a new invitation",
        ));
    }
    let resolved_member_id = target_member.as_ref().map_or_else(
        || {
            if invitation.claims.max_uses > 1 {
                MemberId::new()
            } else {
                invitation.claims.member_id
            }
        },
        |member| member.id,
    );
    let device_id = if invitation.claims.max_uses > 1 {
        DeviceId::new()
    } else {
        invitation.claims.device_id
    };
    let client_tunnel_address = if invitation.claims.max_uses > 1 {
        current
            .allocate_member_address()
            .map_err(|_| ApiError::conflict("the member address pool is exhausted"))?
    } else {
        invitation.claims.client_tunnel_address
    };
    if let Some(member) = &target_member {
        current
            .ensure_device_capacity(member.id)
            .map_err(|error| ApiError::conflict(error.to_string()))?;
    }
    let resolved_role = target_member
        .as_ref()
        .map_or(invitation.claims.role, |member| member.role);
    let result = EnrollmentResult {
        names: request.names.clone(),
        server_id: invitation.claims.server_id,
        member_id: resolved_member_id,
        device_id,
        role: resolved_role,
        administrator: invitation.claims.administrator,
        server_name: invitation.claims.server_name.clone(),
        endpoint: invitation.claims.endpoint.clone(),
        alternate_endpoint_hosts: invitation.claims.alternate_endpoint_hosts.clone(),
        endpoint_discovery_port: invitation.claims.endpoint_discovery_port,
        endpoint_generation: invitation.claims.endpoint_generation,
        client_tunnel_address,
        server_tunnel_address: invitation.claims.server_tunnel_address,
        server_wireguard_public_key: invitation.claims.server_wireguard_public_key.clone(),
        pinned_server_certificate_pem: invitation.claims.pinned_server_certificate_pem.clone(),
        obfuscated_udp: invitation.claims.obfuscated_udp.clone(),
        tcp_fallback: invitation.claims.tcp_fallback.clone(),
        tls_like: invitation.claims.tls_like.clone(),
        ipv6_tunnel_enabled: state.configuration.ipv6_tunnel_enabled,
    };
    let mut next = current.clone();
    if let Some(grant) = next
        .invitations
        .iter_mut()
        .find(|candidate| candidate.claims.invitation_id == invitation.claims.invitation_id)
    {
        grant.uses_consumed += 1;
    }
    next.invitations
        .retain(|grant| grant.uses_consumed < grant.claims.max_uses);
    if target_member.is_none() {
        next.members.push(MemberRecord {
            id: resolved_member_id,
            name: member_name,
            role: invitation.claims.role,
            administrator: invitation.claims.administrator,
            suspended: false,
            policy: invitation.claims.member_policy.clone(),
        });
    }
    next.devices.push(DeviceRecord {
        id: device_id,
        member_id: resolved_member_id,
        name: device_name,
        client_tunnel_address,
        wireguard_public_key: request.device_wireguard_public_key.clone(),
        management_certificate_pem: request.device_management_certificate_pem.clone(),
        certificate_fingerprint: device_fingerprint,
        peer_communication_enabled: false,
    });
    next.enrollment_receipts.push(EnrollmentReceipt {
        invitation_id: invitation.claims.invitation_id,
        claims: invitation.claims.clone(),
        signature: invitation.signature.clone(),
        token_hash: invitation.claims.token_hash.clone(),
        bootstrap_tunnel_address: invitation.claims.bootstrap_tunnel_address,
        bootstrap_wireguard_public_key: invitation.claims.bootstrap_wireguard_public_key.clone(),
        bootstrap_management_certificate_pem: invitation
            .claims
            .bootstrap_management_certificate_pem
            .clone(),
        bootstrap_certificate_fingerprint: caller.certificate_fingerprint,
        device_wireguard_public_key: request.device_wireguard_public_key,
        device_management_certificate_pem: request.device_management_certificate_pem,
        result: result.clone(),
        expires_at_unix: now + ENROLLMENT_HANDOFF_SECONDS,
    });
    commit_authorization(&state, &mut current, next).await?;
    clear_redemption_failures(&state, rate_key);
    Ok(Json(ApiEnvelope::new(result)))
}

pub(super) fn enrollment_matches_receipt(
    request: &EnrollmentRequest,
    receipt: &EnrollmentReceipt,
) -> bool {
    request.names == receipt.result.names
        && request.claims == receipt.claims
        && request.signature == receipt.signature
        && request.device_wireguard_public_key == receipt.device_wireguard_public_key
        && request.device_management_certificate_pem == receipt.device_management_certificate_pem
}

pub(super) fn validate_token_hash(token_hash: &str) -> Result<(), ApiError> {
    let decoded = hex::decode(token_hash)
        .map_err(|_| ApiError::invalid("invitation token hash is invalid"))?;
    if decoded.len() != 32 || token_hash.len() != 64 {
        return Err(ApiError::invalid("invitation token hash is invalid"));
    }
    Ok(())
}

pub(super) fn token_matches(token: &str, expected_hash: &str) -> bool {
    let actual = hex::encode(Sha256::digest(token.as_bytes()));
    actual.len() == expected_hash.len()
        && bool::from(actual.as_bytes().ct_eq(expected_hash.as_bytes()))
}

pub(super) fn redemption_is_limited(
    state: &AppState,
    invitation_id: InvitationId,
    now: u64,
) -> bool {
    let mut failures = state
        .redemption_failures
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let attempts = failures.entry(invitation_id).or_default();
    while attempts
        .front()
        .is_some_and(|timestamp| now.saturating_sub(*timestamp) >= 60)
    {
        attempts.pop_front();
    }
    attempts.len() >= 5
}

pub(super) fn record_redemption_failure(state: &AppState, invitation_id: InvitationId, now: u64) {
    let mut failures = state
        .redemption_failures
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    failures.entry(invitation_id).or_default().push_back(now);
}

pub(super) fn clear_redemption_failures(state: &AppState, invitation_id: InvitationId) {
    let mut failures = state
        .redemption_failures
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    failures.remove(&invitation_id);
}

pub(super) const MIN_LIVE_METRIC_INTERVAL: Duration = Duration::from_millis(250);

pub(super) const MAX_LIVE_METRIC_INTERVAL: Duration = Duration::from_secs(30);

/// Called only after the bearer token, signature and exact stored claims match.
fn resolve_enrollment_names(request: &EnrollmentRequest) -> Result<(String, String), ApiError> {
    let claims = &request.claims;
    if !claims.recipient_names {
        if request.names.is_some() {
            return Err(ApiError::invalid("this invitation fixes its display names"));
        }
        return Ok((claims.member_name.clone(), claims.device_name.clone()));
    }
    let names = request.names.as_ref().ok_or_else(|| {
        ApiError::invalid("choose the member and device display names before joining")
    })?;
    let device_name = validate_display_name(&names.device_name)
        .map_err(|_| ApiError::invalid("device name must contain 1–64 visible characters"))?;
    let member_name = match (claims.target_member_id, &names.member_name) {
        (Some(_), None) => claims.member_name.clone(),
        (None, Some(value)) => validate_display_name(value)
            .map_err(|_| ApiError::invalid("member name must contain 1–64 visible characters"))?,
        _ => {
            return Err(ApiError::invalid(
                "an existing member keeps its name; a new member must choose one",
            ));
        }
    };
    Ok((member_name, device_name))
}
