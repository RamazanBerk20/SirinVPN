//! Member-wide actions keep the existing connected, pinned management boundary.
use super::*;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct MemberPolicyInput {
    server_id: String,
    member_id: String,
    policy: sirinvpn_protocol::MemberPolicy,
}

#[tauri::command]
pub(super) async fn update_member_policy(
    app: tauri::AppHandle,
    input: MemberPolicyInput,
) -> Result<MembershipSnapshot, String> {
    input.policy.validate().map_err(str::to_owned)?;
    let member_id = input
        .member_id
        .parse::<MemberId>()
        .map_err(|_| "The member ID is invalid.".to_owned())?;
    let client = connected_member_client(&app, &input.server_id).await?;
    if !client
        .configuration()
        .await
        .map_err(safe_error)?
        .member_policies_enabled
    {
        return Err("Update this VPS before configuring member access policies.".into());
    }
    client
        .update_member_policy(member_id, &input.policy)
        .await
        .map_err(safe_error)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct MemberSuspensionInput {
    server_id: String,
    member_id: String,
    suspended: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct MemberDevicesRevokeInput {
    server_id: String,
    member_id: String,
    confirmed: bool,
}

async fn connected_member_client(
    app: &tauri::AppHandle,
    server_id: &str,
) -> Result<crate::management_session::ManagementSession, String> {
    let client = crate::management_session::connected(app, server_id).await?;
    if !client
        .configuration()
        .await
        .map_err(safe_error)?
        .member_lifecycle_enabled
    {
        return Err("Update this VPS with the current app before managing member suspension or revoking all devices.".into());
    }
    Ok(client)
}

#[tauri::command]
pub(super) async fn update_member_suspension(
    app: tauri::AppHandle,
    input: MemberSuspensionInput,
) -> Result<MembershipSnapshot, String> {
    let member_id = input
        .member_id
        .parse::<MemberId>()
        .map_err(|_| "The member ID is invalid.".to_owned())?;
    connected_member_client(&app, &input.server_id)
        .await?
        .update_member_suspension(member_id, input.suspended)
        .await
        .map_err(safe_error)
}

#[tauri::command]
pub(super) async fn revoke_member_devices(
    app: tauri::AppHandle,
    input: MemberDevicesRevokeInput,
) -> Result<MembershipSnapshot, String> {
    if !input.confirmed {
        return Err("Confirm revoking all of this member's devices before continuing.".into());
    }
    let member_id = input
        .member_id
        .parse::<MemberId>()
        .map_err(|_| "The member ID is invalid.".to_owned())?;
    connected_member_client(&app, &input.server_id)
        .await?
        .revoke_member_devices(member_id, input.confirmed)
        .await
        .map_err(safe_error)
}
