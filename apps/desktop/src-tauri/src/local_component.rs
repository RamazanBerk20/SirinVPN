//! Update the packaged local helper independently of remote release feeds.
use crate::*;

#[derive(Serialize)]
pub(super) struct LocalComponentUpdateStatus {
    install_available: bool,
    update_required: bool,
}

#[tauri::command]
pub(super) async fn local_component_update_status() -> Result<LocalComponentUpdateStatus, String> {
    tauri::async_runtime::spawn_blocking(|| {
        #[cfg(target_os = "linux")]
        {
            Ok(LocalComponentUpdateStatus {
                install_available: true,
                update_required: helper::packaged_helper_update_required().map_err(safe_error)?,
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            Ok(LocalComponentUpdateStatus {
                install_available: false,
                update_required: true,
            })
        }
    })
    .await
    .map_err(|_| "Checking the VPN component was interrupted. Try again.".to_owned())?
}

#[tauri::command]
pub(super) async fn install_local_vpn_component(
    confirmed: bool,
) -> Result<LocalTunnelStatus, String> {
    if !confirmed {
        return Err("Confirm updating this device’s VPN component first.".into());
    }
    tauri::async_runtime::spawn_blocking(|| {
        let _operation = connection_controller::acquire()?;
        #[cfg(target_os = "linux")]
        {
            helper::prepare_helper_for_connection(true).map_err(safe_error)?;
            let status = invoke_helper("status", None).map_err(safe_error)?;
            if !status.mtu_detection_supported || !status.endpoint_updates_supported {
                return Err("The VPN component is still out of date. Install the current SirinVPN package.".into());
            }
            Ok(status)
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err("Use the current SirinVPN installer to update the Windows VPN service.".into())
        }
    })
    .await
    .map_err(|_| "Updating the VPN component was interrupted. Refresh its status before trying again.".to_owned())?
}
