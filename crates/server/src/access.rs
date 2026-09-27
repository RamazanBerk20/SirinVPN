//! Access.

use super::*;

pub(super) async fn authorize_device(
    state: &AppState,
    caller: &CallerIdentity,
    manager_required: bool,
) -> Result<CallerAuthorization, ApiError> {
    let authorization = match &state.authorization {
        Some(authorization) => {
            let authorization = authorization.read().await;
            return authorize_current(&authorization, caller, manager_required);
        }
        None => {
            let owner = certificate_fingerprint(&state.configuration.owner_certificate_pem)
                .map_err(|_| ApiError::internal())?;
            if owner != caller.certificate_fingerprint {
                return Err(ApiError::forbidden());
            }
            CallerAuthorization {
                role: ServerRole::Owner,
                administrator: false,
                device_id: None,
                wireguard_public_key: None,
            }
        }
    };
    if manager_required && !authorization.can_manage() {
        return Err(ApiError::forbidden());
    }
    Ok(authorization)
}

/// Mutations call this while holding the authorization write lock, so an
/// already-open request cannot act on a revoked, suspended or demoted identity.
pub(super) fn authorize_current(
    authorization: &AuthorizationDocument,
    caller: &CallerIdentity,
    manager_required: bool,
) -> Result<CallerAuthorization, ApiError> {
    let device = authorization
        .device_for_fingerprint(&caller.certificate_fingerprint)
        .ok_or_else(ApiError::forbidden)?;
    let access = authorization
        .access_for_device(device)
        .ok_or_else(ApiError::forbidden)?;
    let caller = CallerAuthorization {
        role: access.role,
        administrator: access.administrator,
        device_id: Some(device.id),
        wireguard_public_key: decode_key(&device.wireguard_public_key).ok(),
    };
    if manager_required && !caller.can_manage() {
        return Err(ApiError::forbidden());
    }
    Ok(caller)
}

pub(super) fn can_manage_member(
    caller: CallerAuthorization,
    role: ServerRole,
    administrator: bool,
) -> bool {
    caller.is_owner() || (caller.administrator && role == ServerRole::Member && !administrator)
}

pub(super) fn caller_member(
    authorization: &AuthorizationDocument,
    caller: CallerAuthorization,
) -> Option<&MemberRecord> {
    let device = authorization
        .devices
        .iter()
        .find(|device| Some(device.id) == caller.device_id)?;
    authorization
        .members
        .iter()
        .find(|member| member.id == device.member_id)
}

pub(super) fn filtered_snapshot(
    authorization: &AuthorizationDocument,
    caller: CallerAuthorization,
) -> MembershipSnapshot {
    let mut snapshot = authorization.snapshot(unix_time());
    if !caller.can_manage() {
        let member_id = caller_member(authorization, caller).map(|member| member.id);
        snapshot
            .members
            .retain(|member| Some(member.id) == member_id);
        snapshot.active_invitations.retain(|summary| {
            authorization.invitations.iter().any(|grant| {
                grant.claims.invitation_id == summary.id
                    && grant.issued_by == member_id
                    && member_id.is_some()
            })
        });
        snapshot.port_forwards.retain(|forward| {
            authorization
                .devices
                .iter()
                .any(|device| device.id == forward.device_id && Some(device.member_id) == member_id)
        });
    }
    snapshot
}

pub(super) fn require_authorization(
    state: &AppState,
) -> Result<Arc<RwLock<AuthorizationDocument>>, ApiError> {
    state.authorization.clone().ok_or_else(|| {
        ApiError::conflict(
            "P1 authorization state is not initialized; run the compatible owner upgrade first",
        )
    })
}

pub(super) async fn commit_authorization(
    state: &AppState,
    current: &mut AuthorizationDocument,
    next: AuthorizationDocument,
) -> Result<(), ApiError> {
    authorization_transaction::commit(
        &authorization_transaction::Host(state),
        &state.recovery,
        current,
        next,
    )
    .await
}

pub(super) fn decoded_transport_peers(
    authorization: &AuthorizationDocument,
) -> Result<Vec<[u8; 32]>> {
    authorization
        .desired_peers(unix_time())
        .into_iter()
        .map(|peer| {
            decode_key(&peer.public_key)
                .map_err(|_| anyhow!("authorization contains an invalid transport peer"))
        })
        .collect()
}
