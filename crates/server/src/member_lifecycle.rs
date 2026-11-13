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

/// Renaming only relabels: it reaches no peer, rule or key, so it never contains traffic.
/// A Member may rename themself, which makes it a rate-limited Member-reachable mutation.
pub(super) async fn rename_member_handler(
    State(state): State<AppState>,
    Extension(identity): Extension<CallerIdentity>,
    AxumPath(member_id): AxumPath<String>,
    Json(request): Json<RenameMemberRequest>,
) -> Result<Json<ApiEnvelope<MembershipSnapshot>>, ApiError> {
    let member_id = member_id
        .parse::<MemberId>()
        .map_err(|_| ApiError::invalid("member identifier is invalid"))?;
    let name = validate_new_display_name(&request.name)
        .map_err(|error| ApiError::invalid(error.to_string()))?;
    let authorization = require_authorization(&state)?;
    let mut current = authorization.write().await;
    let next = renamed_member(&state, &current, &identity, member_id, name)?;
    // A Member renaming themself sees only what the membership view shows them.
    let snapshot = filtered_snapshot(&next, authorize_current(&next, &identity, false)?);
    if next != *current {
        commit_authorization(&state, &mut current, next).await?;
    }
    Ok(Json(ApiEnvelope::new(snapshot)))
}

/// The document after the rename, or why the caller may not rename. Write lock held.
pub(super) fn renamed_member(
    state: &AppState,
    current: &AuthorizationDocument,
    identity: &CallerIdentity,
    member_id: MemberId,
    name: String,
) -> Result<AuthorizationDocument, ApiError> {
    limit_mutation(state, current, identity)?;
    let caller = authorize_current(current, identity, false)?;
    ensure_active_endpoint_authority(current)?;
    let own = caller_member(current, caller).map(|member| member.id);
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
    if !can_manage_member(caller, member.role, member.administrator) && own != Some(member_id) {
        return Err(ApiError::forbidden());
    }
    let mut next = current.clone();
    if member.name == name {
        return Ok(next);
    }
    ensure_person_name_free(current, &name, Some(member_id))?;
    // Device join codes for this member carry its signed name; they would stop matching.
    if current
        .invitations
        .iter()
        .any(|invitation| invitation.claims.target_member_id == Some(member_id))
    {
        return Err(ApiError::conflict(
            "cancel this person's outstanding device join codes before renaming them",
        ));
    }
    next.members
        .iter_mut()
        .find(|member| member.id == member_id)
        .ok_or_else(ApiError::internal)?
        .name = name;
    Ok(next)
}

/// How a person reads a name: NFKC, then simple case folding (`char::to_lowercase`), so
/// "ÅSA", "åsa" and full-width "ＡＳＡ"-style variants collide.
fn person_name_key(name: &str) -> String {
    icu_normalizer::ComposingNormalizerBorrowed::new_nfkc()
        .normalize(name)
        .chars()
        .flat_map(char::to_lowercase)
        .collect()
}

/// Refuses a new person name that another person already uses, so nobody can pose as the
/// Owner or an Admin by name. Only checked when a name is set: duplicates stored before
/// this check still load and keep working.
pub(super) fn ensure_person_name_free(
    document: &AuthorizationDocument,
    name: &str,
    except: Option<MemberId>,
) -> Result<(), ApiError> {
    let key = person_name_key(name);
    if document
        .members
        .iter()
        .any(|member| Some(member.id) != except && person_name_key(&member.name) == key)
    {
        return Err(ApiError::conflict(
            sirinvpn_protocol::PERSON_NAME_TAKEN_MESSAGE,
        ));
    }
    Ok(())
}
