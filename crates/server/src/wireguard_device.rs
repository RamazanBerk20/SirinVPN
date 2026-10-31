//! Devices that join only through a standard WireGuard configuration.

use super::*;
use sirinvpn_protocol::{DeviceSummary, WireGuardDeviceCreateRequest};

/// The issuer generated the key pair, so the VPS never sees the device's private key.
/// Authority mirrors invitation creation; the device then exists like any enrolled one.
pub(super) async fn create_wireguard_device_handler(
    State(state): State<AppState>,
    Extension(caller): Extension<CallerIdentity>,
    Json(request): Json<WireGuardDeviceCreateRequest>,
) -> Result<Json<ApiEnvelope<DeviceSummary>>, ApiError> {
    let invalid = |error: anyhow::Error| ApiError::invalid(error.to_string());
    validate_host(&request.endpoint.host).map_err(|error| ApiError::invalid(error.to_string()))?;
    let member_name = validate_display_name(&request.member_name).map_err(invalid)?;
    let device_name = validate_display_name(&request.device_name).map_err(invalid)?;
    validate_wireguard_public_key(&request.wireguard_public_key).map_err(invalid)?;
    validate_preshared_key(&request.preshared_key).map_err(invalid)?;
    request
        .member_policy
        .validate()
        .map_err(ApiError::invalid)?;

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
    if !caller.can_manage() {
        let permitted = match request.target_member_id {
            Some(id) => id == issuer_id && issuer.policy.add_own_devices,
            None => {
                issuer.policy.invite_members && request.member_policy.is_subset_of(&issuer.policy)
            }
        };
        if !permitted {
            return Err(ApiError::forbidden());
        }
    }
    ensure_active_endpoint_authority(&current)?;
    if current.server_id != request.server_id {
        return Err(ApiError::conflict(
            "the device request belongs to a different server profile",
        ));
    }
    let mut next = current.clone();
    next.prune_expired(unix_time());
    if next
        .endpoint_transition
        .as_ref()
        .is_some_and(|transition| request.endpoint != transition.claims.endpoint)
    {
        return Err(ApiError::conflict(
            "this device uses a stale server endpoint; apply the current signed endpoint update first",
        ));
    }
    let member_id = match request.target_member_id {
        Some(member_id) => {
            let target = next
                .members
                .iter()
                .find(|member| member.id == member_id)
                .ok_or_else(|| {
                    ApiError::new(
                        StatusCode::NOT_FOUND,
                        ErrorCode::InvalidInput,
                        "the target member was not found",
                    )
                })?;
            if !request.member_policy.is_default() {
                return Err(ApiError::invalid(
                    "an additional device inherits the existing member policy",
                ));
            }
            if target.name != member_name {
                return Err(ApiError::conflict(
                    "the target member changed; refresh membership and try again",
                ));
            }
            if !can_manage_member(caller, target.role, target.administrator)
                && !(target.id == issuer_id && target.policy.add_own_devices)
            {
                return Err(ApiError::forbidden());
            }
            next.ensure_device_capacity(member_id)
                .map_err(|error| ApiError::conflict(error.to_string()))?;
            member_id
        }
        None => {
            let member_id = MemberId::new();
            next.members.push(MemberRecord {
                id: member_id,
                name: member_name,
                role: ServerRole::Member,
                administrator: false,
                suspended: false,
                policy: request.member_policy,
            });
            member_id
        }
    };
    let device_id = DeviceId::new();
    next.devices.push(DeviceRecord {
        id: device_id,
        member_id,
        name: device_name,
        client_tunnel_address: next
            .allocate_member_address()
            .map_err(|_| ApiError::conflict("the member address pool is exhausted"))?,
        wireguard_public_key: request.wireguard_public_key,
        management_certificate_pem: String::new(),
        certificate_fingerprint: String::new(),
        peer_communication_enabled: false,
        preshared_key: Some(request.preshared_key),
    });
    next.schema_version = next.required_schema_version();
    next.validate()
        .map_err(|_| ApiError::conflict("the WireGuard key is already in use"))?;
    let device = next
        .snapshot(unix_time())
        .members
        .into_iter()
        .flat_map(|member| member.devices)
        .find(|device| device.id == device_id)
        .ok_or_else(ApiError::internal)?;
    commit_authorization(&state, &mut current, next).await?;
    Ok(Json(ApiEnvelope::new(device)))
}
