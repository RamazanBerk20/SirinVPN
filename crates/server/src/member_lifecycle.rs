//! Serialized member-wide access changes through the existing runtime transaction.
use super::*;

pub(super) async fn update_member_policy_handler(
    State(state): State<AppState>,
    Extension(identity): Extension<CallerIdentity>,
    AxumPath(member_id): AxumPath<String>,
    Json(policy): Json<sirinvpn_protocol::MemberPolicy>,
) -> Result<Json<ApiEnvelope<MembershipSnapshot>>, ApiError> {
    policy.validate().map_err(ApiError::invalid)?;
    let member_id = member_id
        .parse::<MemberId>()
        .map_err(|_| ApiError::invalid("member identifier is invalid"))?;
    let authorization = require_authorization(&state)?;
    let mut current = authorization.write().await;
    let caller = authorize_current(&current, &identity, true)?;
    ensure_active_endpoint_authority(&current)?;
    let member = current
        .members
        .iter()
        .find(|member| member.id == member_id)
        .ok_or_else(|| ApiError::invalid("member was not found"))?;
    if !can_manage_member_lifecycle(caller, member) {
        return Err(ApiError::forbidden());
    }
    if member.policy == policy {
        return Ok(Json(ApiEnvelope::new(current.snapshot(unix_time()))));
    }
    let mut next = current.clone();
    next.set_member_policy(member_id, policy)
        .map_err(|error| ApiError::invalid(error.to_string()))?;
    let snapshot = next.snapshot(unix_time());
    commit_authorization(&state, &mut current, next).await?;
    Ok(Json(ApiEnvelope::new(snapshot)))
}

pub(super) fn can_manage_member_lifecycle(
    caller: CallerAuthorization,
    member: &MemberRecord,
) -> bool {
    member.role != ServerRole::Owner && can_manage_member(caller, member.role, member.administrator)
}

pub(super) async fn update_member_suspension_handler(
    State(state): State<AppState>,
    Extension(identity): Extension<CallerIdentity>,
    AxumPath(member_id): AxumPath<String>,
    Json(request): Json<MemberSuspensionUpdateRequest>,
) -> Result<Json<ApiEnvelope<MembershipSnapshot>>, ApiError> {
    let member_id = member_id
        .parse::<MemberId>()
        .map_err(|_| ApiError::invalid("member identifier is invalid"))?;
    let authorization = require_authorization(&state)?;
    let mut current = authorization.write().await;
    let caller = authorize_current(&current, &identity, true)?;
    ensure_active_endpoint_authority(&current)?;
    let member = current
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
    if !can_manage_member_lifecycle(caller, member) {
        return Err(ApiError::forbidden());
    }
    if member.suspended == request.suspended {
        return Ok(Json(ApiEnvelope::new(current.snapshot(unix_time()))));
    }
    let mut next = current.clone();
    next.set_member_suspended(member_id, request.suspended)
        .map_err(|_| ApiError::internal())?;
    let snapshot = next.snapshot(unix_time());
    commit_authorization(&state, &mut current, next).await?;
    Ok(Json(ApiEnvelope::new(snapshot)))
}

pub(super) async fn revoke_member_devices_handler(
    State(state): State<AppState>,
    Extension(identity): Extension<CallerIdentity>,
    AxumPath(member_id): AxumPath<String>,
    Json(request): Json<MemberDevicesRevokeRequest>,
) -> Result<Json<ApiEnvelope<MembershipSnapshot>>, ApiError> {
    let member_id = member_id
        .parse::<MemberId>()
        .map_err(|_| ApiError::invalid("member identifier is invalid"))?;
    let authorization = require_authorization(&state)?;
    let mut current = authorization.write().await;
    let caller = authorize_current(&current, &identity, true)?;
    ensure_active_endpoint_authority(&current)?;
    if !request.confirmed {
        return Err(ApiError::invalid(
            "confirm revoking all of this member's devices",
        ));
    }
    // A retry after a lost success response has no remaining access to revoke.
    let Some(member) = current.members.iter().find(|member| member.id == member_id) else {
        return Ok(Json(ApiEnvelope::new(current.snapshot(unix_time()))));
    };
    if !can_manage_member_lifecycle(caller, member) {
        return Err(ApiError::forbidden());
    }
    let mut next = current.clone();
    next.revoke_member_devices(member_id)
        .map_err(|_| ApiError::internal())?;
    let snapshot = next.snapshot(unix_time());
    commit_authorization(&state, &mut current, next).await?;
    Ok(Json(ApiEnvelope::new(snapshot)))
}
