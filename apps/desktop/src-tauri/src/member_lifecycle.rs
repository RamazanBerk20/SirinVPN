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
        return Err("Update this server to set access policies.".into());
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
        return Err("Update the server to suspend members or revoke all their devices.".into());
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
        return Err("Confirm revoking all of this member’s devices first.".into());
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

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct MemberRenameInput {
    server_id: String,
    member_id: String,
    name: String,
}

/// `person_has_join_codes` when the VPS refuses because the person still has device join
/// codes, which carry their signed name: the UI can cancel those codes and retry.
#[tauri::command]
pub(super) async fn rename_member(
    app: tauri::AppHandle,
    input: MemberRenameInput,
) -> Result<MembershipSnapshot, CommandError> {
    let member_id = input
        .member_id
        .parse::<MemberId>()
        .map_err(|_| "The member ID is invalid.")?;
    sirinvpn_protocol::validate_server_name(&input.name)
        .map_err(|_| "Enter a name with 1 to 64 visible characters.")?;
    let client = crate::management_session::connected(&app, &input.server_id).await?;
    if !client
        .configuration()
        .await
        .map_err(safe_error)?
        .person_rename_enabled
    {
        return Err("Update this server to rename people.".into());
    }
    match client.rename_member(member_id, input.name).await {
        Err(
            error @ ManagementError::RequestRejected {
                code: sirinvpn_protocol::ErrorCode::ConflictDetected,
                ..
            },
        ) => {
            // A conflict has other causes too; only outstanding codes for this person mean this.
            let has_codes = client.membership().await.is_ok_and(|snapshot| {
                snapshot
                    .active_invitations
                    .iter()
                    .any(|invitation| invitation.target_member_id == Some(member_id))
            });
            Err(if has_codes {
                command_error(crate::command_error::Rejected {
                    refused: crate::command_error::Refused::PersonHasJoinCodes,
                    error,
                })
            } else {
                command_error(error)
            })
        }
        result => result.map_err(command_error),
    }
}
