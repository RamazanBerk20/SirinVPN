//! Devices added for a standard WireGuard app or router.

use super::*;
use sirinvpn_core::WireGuardDeviceDraft;

#[derive(Deserialize)]
pub(super) struct WireGuardDeviceInput {
    server_id: String,
    member_name: String,
    device_name: String,
    target_member_id: Option<String>,
    #[serde(default)]
    member_policy: sirinvpn_protocol::MemberPolicy,
    /// Chosen in a save dialog; only the configuration generated here is written to it.
    path: Option<String>,
}

#[derive(Serialize)]
pub(super) struct WireGuardDeviceResult {
    device_id: DeviceId,
    qr_svg: String,
}

impl Drop for WireGuardDeviceResult {
    fn drop(&mut self) {
        self.qr_svg.zeroize();
    }
}

/// The private key stays in native memory except inside the QR image and the chosen file.
#[tauri::command]
pub(super) async fn create_wireguard_device(
    app: tauri::AppHandle,
    input: WireGuardDeviceInput,
) -> Result<WireGuardDeviceResult, String> {
    let path = input.path.filter(|path| !path.trim().is_empty()).map(PathBuf::from);
    // Checked first so a taken path cannot leave a device whose key was never saved.
    if path.as_ref().is_some_and(|path| path.symlink_metadata().is_ok()) {
        return Err("That file already exists. Choose a new file name.".into());
    }
    let target_member_id = input
        .target_member_id
        .map(|id| id.parse::<MemberId>())
        .transpose()
        .map_err(|_| "The member ID is invalid.".to_owned())?;
    let client = crate::management_session::connected(&app, &input.server_id).await?;
    if !client
        .configuration()
        .await
        .map_err(safe_error)?
        .wireguard_devices_enabled
    {
        return Err("Update this server to add WireGuard app devices.".into());
    }
    let draft = WireGuardDeviceDraft::new(
        &client.profile,
        &input.member_name,
        &input.device_name,
        target_member_id,
        input.member_policy,
    )
    .map_err(safe_error)?;
    let device = client
        .create_wireguard_device(draft.request())
        .await
        .map_err(safe_error)?;
    let config = draft.finish(device).map_err(safe_error)?;
    if let Some(path) = path {
        config.save(&path).map_err(|_| {
            "The device was added, but its file could not be saved. Revoke it and add it again."
                .to_owned()
        })?;
    }
    Ok(WireGuardDeviceResult {
        device_id: config.device().id,
        qr_svg: render_invitation_qr(config.expose())?,
    })
}
