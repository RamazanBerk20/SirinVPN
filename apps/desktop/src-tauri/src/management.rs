//! Management.

use super::*;

#[tauri::command]
pub(super) async fn run_diagnostics(
    app: tauri::AppHandle,
    server_id: String,
) -> Result<DiagnosticReport, String> {
    crate::diagnostics::run(app, server_id).await
}

#[tauri::command]
pub(super) async fn membership(
    app: tauri::AppHandle,
    server_id: String,
) -> Result<MembershipSnapshot, String> {
    let session = crate::management_session::connected_read(&app, &server_id).await?;
    session.read(session.membership()).await
}

#[tauri::command]
pub(super) async fn server_configuration(
    app: tauri::AppHandle,
    server_id: String,
) -> Result<CurrentConfiguration, String> {
    let session = crate::management_session::connected_read(&app, &server_id).await?;
    session.read(session.configuration()).await
}

#[tauri::command]
pub(super) async fn create_invitation(
    app: tauri::AppHandle,
    input: InvitationInput,
) -> Result<InvitationResult, String> {
    let client = crate::management_session::connected(&app, &input.server_id).await?;
    let mut profile = client.profile.clone();
    let status = client.status().await.map_err(safe_error)?;
    if let Some(role) = status.caller_role {
        profile.role = role;
        profile.administrator = status.caller_administrator;
    }
    if input.recipient_names
        && !client
            .configuration()
            .await
            .map_err(safe_error)?
            .recipient_names_enabled
    {
        return Err("Update this VPS to support invitations where recipients choose their member and device names.".into());
    }
    let advanced = input.target_member_id.is_some() || input.administrator;
    let max_uses = input.max_uses.unwrap_or(1);
    if (max_uses > 1
        || !input.member_policy.is_default()
        || (profile.role != ServerRole::Owner && !profile.administrator))
        && !client
            .configuration()
            .await
            .map_err(safe_error)?
            .reusable_invitations_enabled
    {
        return Err("Update this VPS before using reusable invitations, member policies or delegated invitations.".into());
    }
    if advanced
        && !client
            .configuration()
            .await
            .map_err(safe_error)?
            .advanced_invitations_enabled
    {
        return Err(
            "Update the SirinVPN server before creating Admin or additional-device invitations."
                .to_owned(),
        );
    }
    let (member_name, target) = match input.target_member_id {
        Some(member_id) => {
            let member_id = member_id
                .parse::<MemberId>()
                .map_err(|_| "The member ID is invalid.".to_owned())?;
            let snapshot = client.membership().await.map_err(safe_error)?;
            let member = snapshot
                .members
                .into_iter()
                .find(|member| member.id == member_id)
                .ok_or_else(|| {
                    "The invited member no longer exists. Refresh access and try again.".to_owned()
                })?;
            (
                member.name,
                InvitationTarget {
                    member_id: Some(member.id),
                    role: Some(member.role),
                    administrator: member.administrator,
                },
            )
        }
        None => (
            if input.recipient_names {
                "Invited member".into()
            } else {
                input.member_name
            },
            InvitationTarget {
                administrator: input.administrator,
                ..InvitationTarget::default()
            },
        ),
    };
    let draft = InvitationDraft::new_for_target(
        &profile,
        &member_name,
        if input.recipient_names {
            "New device"
        } else {
            &input.device_name
        },
        input.expires_in_seconds,
        target,
    )
    .map_err(safe_error)?
    .with_recipient_names(input.recipient_names)
    .with_policy(max_uses, input.member_policy)
    .map_err(safe_error)?;
    let response = client
        .create_invitation(draft.request())
        .await
        .map_err(safe_error)?;
    let code = draft.finish(response).map_err(safe_error)?;
    let qr_svg = render_invitation_qr(code.qr_payload())?;
    Ok(InvitationResult {
        invitation_id: code.invitation_id(),
        expires_at_unix: code.expires_at_unix(),
        code: code.expose().to_owned(),
        qr_svg,
    })
}

pub(super) fn render_invitation_qr(payload: &str) -> Result<String, String> {
    let code = QrCode::with_error_correction_level(payload.as_bytes(), EcLevel::L)
        .map_err(|_| "The invitation is too large to display as a QR code.".to_owned())?;
    Ok(code
        .render::<svg::Color>()
        // One SVG unit per module lets the UI use whole screen pixels per module.
        .module_dimensions(1, 1)
        .dark_color(svg::Color("#07101f"))
        .light_color(svg::Color("#ffffff"))
        .build())
}

#[tauri::command]
pub(super) async fn cancel_invitation(
    app: tauri::AppHandle,
    server_id: String,
    invitation_id: String,
) -> Result<(), String> {
    let invitation_id = invitation_id
        .parse::<InvitationId>()
        .map_err(|_| "The invitation ID is invalid.".to_owned())?;
    crate::management_session::connected(&app, &server_id)
        .await?
        .cancel_invitation(invitation_id)
        .await
        .map_err(safe_error)
}

#[tauri::command]
pub(super) async fn rename_device(
    app: tauri::AppHandle,
    input: DeviceRenameInput,
) -> Result<MembershipSnapshot, String> {
    let device_id = input
        .device_id
        .parse::<DeviceId>()
        .map_err(|_| "The device ID is invalid.".to_owned())?;
    crate::management_session::connected(&app, &input.server_id)
        .await?
        .rename_device(device_id, input.name)
        .await
        .map_err(safe_error)
}

#[tauri::command]
pub(super) async fn revoke_device(
    app: tauri::AppHandle,
    server_id: String,
    device_id: String,
) -> Result<MembershipSnapshot, String> {
    let device_id = device_id
        .parse::<DeviceId>()
        .map_err(|_| "The device ID is invalid.".to_owned())?;
    crate::management_session::connected(&app, &server_id)
        .await?
        .revoke_device(device_id)
        .await
        .map_err(safe_error)
}

#[tauri::command]
pub(super) async fn update_device_peer_communication(
    app: tauri::AppHandle,
    input: DevicePeerCommunicationInput,
) -> Result<MembershipSnapshot, String> {
    let device_id = input
        .device_id
        .parse::<DeviceId>()
        .map_err(|_| "The device ID is invalid.".to_owned())?;
    let client = crate::management_session::connected(&app, &input.server_id).await?;
    if !client
        .configuration()
        .await
        .map_err(safe_error)?
        .peer_isolation_enabled
    {
        return Err("Repair this SirinVPN server before changing peer communication.".to_owned());
    }
    client
        .update_device_peer_communication(device_id, input.enabled)
        .await
        .map_err(safe_error)
}

#[tauri::command]
pub(super) async fn create_port_forward(
    app: tauri::AppHandle,
    input: PortForwardCreateInput,
) -> Result<MembershipSnapshot, String> {
    if !input.confirmed {
        return Err("Confirm the public port exposure before continuing.".to_owned());
    }
    let device_id = input
        .device_id
        .parse::<DeviceId>()
        .map_err(|_| "The device ID is invalid.".to_owned())?;
    let client = crate::management_session::connected(&app, &input.server_id).await?;
    if !client
        .configuration()
        .await
        .map_err(safe_error)?
        .port_forwarding_enabled
    {
        return Err("Repair this SirinVPN server before managing port forwards.".to_owned());
    }
    client
        .create_port_forward(&PortForwardCreateRequest {
            protocol: input.protocol,
            public_port: input.public_port,
            device_id,
            device_port: input.device_port,
        })
        .await
        .map_err(safe_error)
}

#[tauri::command]
pub(super) async fn remove_port_forward(
    app: tauri::AppHandle,
    input: PortForwardRemoveInput,
) -> Result<MembershipSnapshot, String> {
    let client = crate::management_session::connected(&app, &input.server_id).await?;
    if !client
        .configuration()
        .await
        .map_err(safe_error)?
        .port_forwarding_enabled
    {
        return Err("Repair this SirinVPN server before managing port forwards.".to_owned());
    }
    client
        .remove_port_forward(input.protocol, input.public_port)
        .await
        .map_err(safe_error)
}

#[tauri::command]
pub(super) async fn update_member_access(
    app: tauri::AppHandle,
    input: MemberAccessInput,
) -> Result<MembershipSnapshot, String> {
    let member_id = input
        .member_id
        .parse::<MemberId>()
        .map_err(|_| "The member ID is invalid.".to_owned())?;
    let client = crate::management_session::connected(&app, &input.server_id).await?;
    let status = client.status().await.map_err(safe_error)?;
    if let Some(role) = status.caller_role {
        client
            .retain_access(&app, role, status.caller_administrator)
            .await?;
    }
    if status.caller_role != Some(ServerRole::Owner) {
        return Err("Only the owner can change Admin access.".to_owned());
    }
    if !client
        .configuration()
        .await
        .map_err(safe_error)?
        .advanced_invitations_enabled
    {
        return Err("Update the SirinVPN server before changing Admin access.".to_owned());
    }
    client
        .update_member_access(member_id, input.administrator)
        .await
        .map_err(safe_error)
}

#[tauri::command]
pub(super) async fn transfer_ownership(
    app: tauri::AppHandle,
    input: OwnershipTransferInput,
) -> Result<MembershipSnapshot, String> {
    if !input.confirmed {
        return Err("Confirm the ownership transfer before continuing.".to_owned());
    }
    let destination_device_id = input
        .destination_device_id
        .parse::<DeviceId>()
        .map_err(|_| "The destination device ID is invalid.".to_owned())?;
    let client = crate::management_session::connected(&app, &input.server_id).await?;
    let status = client.status().await.map_err(safe_error)?;
    if status.caller_role != Some(ServerRole::Owner) {
        return Err("Only the owner can transfer ownership.".to_owned());
    }
    if !client
        .configuration()
        .await
        .map_err(safe_error)?
        .ownership_transfer_enabled
    {
        return Err("Update the SirinVPN server before transferring ownership.".to_owned());
    }
    let snapshot = client
        .transfer_ownership(destination_device_id)
        .await
        .map_err(safe_error)?;
    client.retain_access(&app, ServerRole::Member, true).await.map_err(|_| {
            "Ownership was transferred on the VPS, but this device's local access level could not be saved. Reconnect to refresh it.".to_owned()
    })?;
    Ok(snapshot)
}
